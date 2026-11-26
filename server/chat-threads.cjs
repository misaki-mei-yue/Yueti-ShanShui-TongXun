'use strict';

const { createHash } = require('node:crypto');

function directThreadKey(first, second) {
  return 'direct:' + [first, second].sort().join(':');
}

// This is a read-only index. Membership, writes, reads, restore grants and
// signatures continue to use each original physical chat ID.
function createChatThreads(db) {
  const readRooms = db.prepare(`
    WITH RECURSIVE lineage(id) AS (
      SELECT chat_id FROM members WHERE user_id=:user
      UNION
      SELECT id FROM chats WHERE id=:room
      UNION
      SELECT a.chat_id FROM chat_archives a JOIN lineage l ON l.id=a.successor_id
      UNION
      SELECT a.successor_id FROM chat_archives a JOIN lineage l ON l.id=a.chat_id
    )
    SELECT c.id,c.kind,c.direct_key,c.created_at,c.owner_id,
      a.chat_id IS NOT NULL AS archived, previous.chat_id AS previous_id,
      (c.id=:room OR EXISTS(SELECT 1 FROM members me WHERE me.chat_id=c.id AND me.user_id=:user)) AS visible,
      (SELECT json_group_array(user_id ORDER BY user_id) FROM members WHERE chat_id=c.id AND user_id<>'ai') AS humans,
      EXISTS(SELECT 1 FROM members m LEFT JOIN users u ON u.id=m.user_id
        WHERE m.chat_id=c.id AND m.user_id<>'ai' AND u.id IS NULL) AS unknown_human,
      EXISTS(SELECT 1 FROM members bot WHERE bot.chat_id=c.id AND bot.user_id='ai') AS has_ai,
      CASE WHEN c.kind='group' THEN (SELECT max(revision) FROM manifests WHERE chat_id=c.id) END AS revision,
      CASE WHEN c.kind='group' THEN (SELECT max(seq) FROM messages WHERE chat_id=c.id) END AS last_seq
    FROM lineage l JOIN chats c ON c.id=l.id
    LEFT JOIN chat_archives a ON a.chat_id=c.id
    LEFT JOIN chat_archives previous ON previous.successor_id=c.id`);

  const pastPeople = db.prepare(`
    SELECT 1 FROM manifests mf,json_each(mf.payload,'$.members') signer
      WHERE mf.chat_id=:id AND mf.revision>:revision AND NOT EXISTS(
        SELECT 1 FROM members m WHERE m.chat_id=:id AND m.user_id=json_extract(signer.value,'$.userId')
      )
    UNION ALL
    SELECT 1 FROM messages msg WHERE msg.chat_id=:id AND msg.seq>:seq AND (
      (msg.sender_id<>'ai' AND NOT EXISTS(SELECT 1 FROM members m WHERE m.chat_id=:id AND m.user_id=msg.sender_id))
      OR msg.content_version=0 OR :signed=0
    ) LIMIT 1`);
  const checkedRooms = new Map();
  function familyChanged(room) {
    const revision = room.revision || 0, seq = room.last_seq || 0;
    const prior = checkedRooms.get(room.id);
    const same = prior && prior.humans === room.humans && prior.revision <= revision && prior.seq <= seq;
    if (same && (prior.changed || (prior.revision === revision && prior.seq === seq))) return prior.changed;
    const changed = !!pastPeople.get({id: room.id, revision: same ? prior.revision : 0, seq: same ? prior.seq : 0, signed: revision});
    if (checkedRooms.size >= 2048) checkedRooms.delete(checkedRooms.keys().next().value);
    checkedRooms.set(room.id,{humans:room.humans,revision,seq,changed});
    return changed;
  }

  function buildIndex(userId,roomId) {
    const rooms = readRooms.all({ user: userId, room:roomId });
    const byId = new Map(rooms.map(room => [room.id, room]));
    const roots = new Map(), familyKeys = new Map(), buckets = new Map(), visible = new Map();
    function rootOf(room) {
      const path = new Set();
      while (room.previous_id && !roots.has(room.id) && !path.has(room.id)) {
        path.add(room.id);
        room = byId.get(room.previous_id);
      }
      const root = roots.get(room.id) || (path.has(room.id) ? [...path].sort()[0] : room.id);
      for (const id of path) roots.set(id,root);
      return root;
    }
    for (const room of rooms) {
      const people = JSON.parse(room.humans);
      if (!room.unknown_human && (room.kind === 'direct' || room.kind === 'group') && people.length === 2)
        room.key = directThreadKey(...people);
      if (!room.unknown_human && people.length === 1 && people[0] === room.owner_id) {
        const kind = room.kind === 'group' ? (room.has_ai ? 'ai' : 'notes') : room.kind;
        if (kind === 'ai' || kind === 'notes') room.key = kind + ':' + room.owner_id;
      }
      if (room.kind === 'group') {
        const root = rootOf(room);
        room.root = root;
        // A group which ever included another person is a separate history.
        // Two groups with identical names or current rosters remain distinct.
        if (!room.key || (!room.has_ai && !room.revision) || familyChanged(room) || (familyKeys.has(root) && familyKeys.get(root) !== room.key))
          familyKeys.set(root, null);
        else familyKeys.set(root, room.key);
      }
    }
    for (const room of rooms) {
      if (!room.visible) continue;
      if (room.kind === 'group')
        room.key = familyKeys.get(room.root) || 'group:' + createHash('sha256').update(room.root).digest('hex');
      room.key ||= 'room:' + room.id;
      if (!buckets.has(room.key)) buckets.set(room.key, []);
      buckets.get(room.key).push(room);
      visible.set(room.id,room);
    }
    const primary = new Map();
    for (const [key, entries] of buckets) {
      entries.sort((a,b) => a.archived-b.archived
        || Number(a.kind==='group')-Number(b.kind==='group')
        || Number(!a.direct_key)-Number(!b.direct_key)
        || (a.archived ? b.created_at.localeCompare(a.created_at) : a.created_at.localeCompare(b.created_at))
        || a.id.localeCompare(b.id));
      primary.set(key,entries[0]);
    }
    return {
      kind(id) {
        const room=visible.get(id);
        return room?.key.startsWith('room:') ? room.kind : room?.key.split(':',1)[0];
      },
      activeId(key) {
        const room = primary.get(key);
        return room && !room.archived ? room.id : null;
      },
      primaryId(id) { return primary.get(visible.get(id)?.key)?.id; },
      decorate(chat) {
        const room = visible.get(chat.id);
        if (!room) return chat;
        if (chat.predecessorId && !visible.has(chat.predecessorId)) delete chat.predecessorId;
        if (chat.successorId && !visible.has(chat.successorId)) delete chat.successorId;
        return {...chat,threadKey:room.key,threadPrimaryId:primary.get(room.key).id};
      }
    };
  }
  return {
    forUser: userId => buildIndex(userId,null),
    groupKind: roomId => buildIndex(null,roomId).kind(roomId)
  };
}
module.exports = {createChatThreads,directThreadKey};
