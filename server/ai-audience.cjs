'use strict';

// Personal grants apply to the account's AI chat and two-person conversations.
// A group grant applies only inside that group. The provider key is still
// encrypted on the administrator's device for the union of eligible identities.
function createAIAudience({ db, fail, exactKeys, isGroup }) {
  db.exec(`CREATE TABLE IF NOT EXISTS ai_personal_grants(user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE);
    CREATE TABLE IF NOT EXISTS ai_group_grants(chat_id TEXT PRIMARY KEY REFERENCES chats(id) ON DELETE CASCADE);`);
  const get = (sql, ...params) => db.prepare(sql).get(...params);
  const all = (sql, ...params) => db.prepare(sql).all(...params);
  const personal = userId => !!get('SELECT 1 FROM ai_personal_grants WHERE user_id=?', userId);
  // Every explicit configuration keeps the administrator as a personal grantee.
  const configured = () => !!get('SELECT 1 FROM ai_personal_grants LIMIT 1');
  function groups() {
    return all(`SELECT c.id,c.name,m.user_id FROM chats c JOIN members m ON m.chat_id=c.id
      WHERE c.kind='group' AND m.user_id<>'ai' AND NOT EXISTS(SELECT 1 FROM chat_archives a WHERE a.chat_id=c.id)
      ORDER BY c.name,c.id,m.user_id`).reduce((groups, row) => {
      let group = groups.at(-1);
      if (group?.id !== row.id) groups.push(group = { id: row.id, name: row.name, memberIds: [] });
      group.memberIds.push(row.user_id);
      return groups;
    }, []).filter(group => group.memberIds.length > 2 || isGroup(group.id));
  }
  function adminView(metadata) {
    const candidateGroups = groups();
    const recipients = new Set((metadata?.recipients || []).map(r => r.userId));
    const scoped = configured();
    const userIds = scoped ? all('SELECT user_id FROM ai_personal_grants ORDER BY user_id').map(row => row.user_id) : [...recipients];
    const groupIds = candidateGroups.filter(g => scoped ? groupEnabled(g.id) :
      // Avoid extending a previous grant to a previously unapproved member
      // merely because the administrator saved an unrelated model setting.
      g.memberIds.every(id => recipients.has(id)) && legacyAIGroup(g.id)).map(g => g.id);
    return { candidateGroups, audience: { userIds, groupIds } };
  }
  const legacyAIGroup = id => !!get("SELECT 1 FROM members WHERE chat_id=? AND user_id='ai'", id);
  const groupEnabled = id => !!get('SELECT 1 FROM ai_group_grants WHERE chat_id=?', id);
  function allows(userId, chatId, displayKind) {
    if (!['ai', 'direct', 'group'].includes(displayKind)) return false;
    if (!configured()) return displayKind !== 'group' || legacyAIGroup(chatId);
    return displayKind === 'group' ? groupEnabled(chatId) : personal(userId);
  }
  function canReceive(userId) {
    return !configured() || personal(userId) || all(`SELECT g.chat_id AS id FROM ai_group_grants g JOIN members m ON m.chat_id=g.chat_id
      WHERE m.user_id=? AND NOT EXISTS(SELECT 1 FROM chat_archives a WHERE a.chat_id=g.chat_id)
      `, userId).some(group => isGroup(group.id));
  }
  function commit(audience, payload, repeatedRevision = false) {
    if (audience === undefined) {
      if (configured()) fail(409, '此服务器已设置个人与群聊授权，请更新客户端后保存。');
      return;
    }
    exactKeys(audience, ['userIds', 'groupIds'], 'AI 授权范围');
    const uuid = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
    for (const ids of [audience.userIds, audience.groupIds]) {
      if (!Array.isArray(ids) || ids.some(id => typeof id !== 'string' || !uuid.test(id)) || ids.length !== new Set(ids).size) fail(400, '授权对象列表无效');
    }
    if (repeatedRevision) {
      const saved = adminView(payload).audience;
      const same = (one, two) => one.length === two.length && one.every(id => two.includes(id));
      if (!same(saved.userIds, audience.userIds) || !same(saved.groupIds, audience.groupIds)) fail(409, '更改授权范围需要管理员重新签署 AI 配置');
      return;
    }
    if (!audience.userIds.includes(payload.ownerId)) fail(400, '请保留管理员自身的授权');
    if (audience.userIds.some(id => !get('SELECT 1 FROM users WHERE id=?', id))) fail(409, '授权账户已变化，请刷新后重新保存');
    const expected = new Set(audience.userIds);
    const byId = new Map(groups().map(group => [group.id, group]));
    for (const groupId of audience.groupIds) {
      const group = byId.get(groupId);
      if (!group) fail(409, '群聊已变化，请重新打开授权设置');
      for (const member of group.memberIds) if (get('SELECT 1 FROM identities WHERE user_id=?', member)) expected.add(member);
    }
    if (payload.recipients && (expected.size !== payload.recipients.length || payload.recipients.some(r => !expected.has(r.userId)))) fail(409, '授权范围与加密身份清单不一致，请刷新后重新保存');
    db.exec('DELETE FROM ai_personal_grants; DELETE FROM ai_group_grants;');
    const addPersonal = db.prepare('INSERT INTO ai_personal_grants(user_id) VALUES(?)');
    const addGroup = db.prepare('INSERT INTO ai_group_grants(chat_id) VALUES(?)');
    for (const userId of audience.userIds) addPersonal.run(userId);
    for (const groupId of audience.groupIds) addGroup.run(groupId);
  }
  return { adminView, allows, canReceive, commit };
}
module.exports = { createAIAudience };
