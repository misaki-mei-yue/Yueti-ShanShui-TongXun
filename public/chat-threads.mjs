// Keep physical rooms intact. Message signatures, attachment access and send
// permissions are all bound to their original room.
export function indexChatThreads(rooms, userId) {
  const byId = new Map(rooms.map(room => [room.id,room]));
  const threads = new Map(), byRoom = new Map();
  function endOfLineage(room) {
    const seen = new Set();
    while (byId.has(room.successorId) && !seen.has(room.id)) {
      seen.add(room.id);
      room = byId.get(room.successorId);
    }
    return room;
  }
  const knownGroups = new Set();
  for (const room of rooms) {
    if (!room.threadKey && room.kind === 'group' && (room.e2eeRevision > 1
        || room.members.filter(member => member.id !== 'ai').length > 2
        || (!room.e2eeRevision && (room.lastMessage || !room.members.some(member => member.id === 'ai'))))) {
      knownGroups.add(endOfLineage(room).id);
    }
  }
  function fallbackKey(entry) {
    const room = endOfLineage(entry);
    if (knownGroups.has(room.id)) return 'room:' + room.id;
    const kind = room.displayKind || room.kind;
    const humans = room.members.filter(member => member.id !== 'ai').map(member => member.id);
    if (kind === 'direct' && humans.length === 2 && humans.includes(userId)
        && (room.kind === 'direct' || room.e2eeRevision <= 1)) {
      return 'direct:' + humans.find(id => id !== userId);
    }
    if (['notes','ai'].includes(room.kind) && humans.length === 1 && humans[0] === userId) return room.kind + ':' + userId;
    return 'room:' + room.id;
  }
  for (const room of rooms) {
    const kind = room.displayKind || room.kind;
    const audience = kind === 'direct' ? room.members.filter(member => member.id !== 'ai').map(member => member.id).sort() : [];
    const key = room.threadKey ? JSON.stringify([room.threadKey,kind,audience]) : 'legacy:' + fallbackKey(room);
    if (!threads.has(key)) threads.set(key,{rooms:[],primary:null,historicalGroup:!room.threadKey && knownGroups.has(endOfLineage(room).id)});
    const thread = threads.get(key);
    thread.rooms.push(room);
    byRoom.set(room.id,thread);
  }
  for (const thread of threads.values()) {
    const declared = byId.get(thread.rooms[0].threadPrimaryId);
    const ranked = [...thread.rooms].sort((a,b) => Number(!!a.archived) - Number(!!b.archived)
      || Number(a.kind === 'group') - Number(b.kind === 'group') || a.id.localeCompare(b.id));
    thread.primary = declared && byRoom.get(declared.id) === thread && (!declared.archived || ranked[0].archived) ? declared : ranked[0];
  }
  return {threads:[...threads.values()],byRoom,byId};
}

export function threadSummary({primary,rooms}) {
  const latest = rooms.reduce((result,room) => room.lastMessage && (!result || room.lastMessage.seq > result.lastMessage.seq) ? room : result,null);
  return {...primary,lastMessage:latest?.lastMessage,latestArchived:!!latest?.archived,
    updatedAt:latest?.lastMessage.createdAt || primary.updatedAt,
    unread:rooms.reduce((total,room) => total + (room.unread || 0),0),
    archiveAssistPending:rooms.some(room => room.archiveAssistPending)};
}
