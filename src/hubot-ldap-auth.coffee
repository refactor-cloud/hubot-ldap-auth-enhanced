# Description:
#   Delegate authorization for Hubot user actions to LDAP
#
# Configuration: (ENV - json - description)
# The json config is located under the 'ldap_auth' key
#   HUBOT_LDAP_AUTH_HOST - host - the address of the LDAP server
#   HUBOT_LDAP_AUTH_BIND_DN - bind_dn - the bind DN to authenticate with
#   HUBOT_LDAP_AUTH_BIND_PASSWORD - bind_password - the bind password to authenticate with
#   HUBOT_LDAP_AUTH_USER_SEARCH_FILTER - user_search_filter - the ldap filter search for a specific user - e.g. 'cn={0}' where '{0}' will be replaced by the hubot user attribute
#   HUBOT_LDAP_AUTH_GROUP_MEMBERSHIP_ATTRIBUTE - group_membership_attribute - the member attribute within the user object
#   HUBOT_LDAP_AUTH_GROUP_MEMBERSHIP_FILTER - group_membership_filter - the membership filter to find groups based on user DN - e.g. 'member={0}' where '{0}' will be replaced by user DN
#   HUBOT_LDAP_AUTH_GROUP_MEMBERSHIP_SEARCH_METHOD - group_membership_search_method - (filter | attribute) how to find groups belong to users
#   HUBOT_LDAP_AUTH_ROLES_TO_INCLUDE - roles_to_include - comma separated group names that will be used as roles, all the rest of the groups will be filtered out. Json datatype needs to be array.
#   HUBOT_LDAP_AUTH_USE_ONLY_LISTENER_ROLES - use_only_listener_roles - if true, groups will only be filtered by all listener options and ROLES_TO_INCLUDE will be ignored
#   HUBOT_LDAP_AUTH_BASE_DN - base_dn - search DN to start finding users and groups within the ldap directory
#   HUBOT_LDAP_AUTH_LDAP_USER_ATTRIBUTE - ldap_user_attribute - the ldap attribute to match hubot users within the ldap directory
#   HUBOT_LDAP_AUTH_HUBOT_USER_ATTRIBUTE - hubot_user_attribute - the hubot user attribute to search for a user within the ldap directory
#   HUBOT_LDAP_AUTH_LDAP_GROUP_ATTRIBUTE - ldap_group_attribute - the ldap attribute of a group that will be used as role name
#   HUBOT_LDAP_AUTH_REFRESH_TIME - refresh_time - time in millisecods to refresh the roles and users
#   HUBOT_LDAP_AUTH_DN_ATTRIBUTE_NAME - dn_attirbute_name - the dn attribute name, used for queries by DN. In ActiveDirectory should be distinguishedName
#   HUBOT_LDAP_AUTH_USERNAME_REWRITE_RULE - username_rewrite_rule - regex for rewriting the hubot username to the one used in ldap - e.g. '@(.+):matrix.org' where the first capturing group will be used as username. No subsitution if omitted
#   HUBOT_LDAP_AUTH_ROOM_ATTRIBUTE - room_attribute - the ldap attribute for room auto creation/auto join
#   HUBOT_LDAP_AUTH_ROOM_SEARCH_TREE - room_search_tree - ldap subtree to search room names
#
# Commands:
#   hubot what roles does <user> have - Find out what roles a user has
#   hubot what roles do I have - Find out what roles you have
#   hubot refresh roles
#   hubot refresh roles! - Refresh also already known user DNs
#   hubot who has <roleName> role

_ = require 'lodash'
LDAP = require 'ldapjs'
Promise = require 'bluebird'
config = require 'config'

ENV_PREFIX = "HUBOT_LDAP_AUTH"
JSON_PREFIX = "ldap_auth"

client = undefined

module.exports = (robot) ->
  loadConfigValue = (name, defaultValue, func...) ->
    result = process.env["#{ENV_PREFIX}_#{name.toUpperCase()}"]
    if result
      return if func.length == 0 then result else func[0] result

    if config.has("#{JSON_PREFIX}.#{name}")
      result = config.get("#{JSON_PREFIX}.#{name}")
      return if func.length == 0 or func[func.length - 1] == undefined then result else func[func.length - 1] result

    defaultValue

  ldapHost = loadConfigValue "host", 'ldap://127.0.0.1:389'
  bindDn = loadConfigValue "bind_dn"
  bindPassword = loadConfigValue "bind_password"

  userSearchFilter = loadConfigValue "user_search_filter",  'cn={0}'
  dnAttributeName = loadConfigValue "dn_attribute_name", 'dn'
  groupMembershipAttribute = loadConfigValue "group_membership_attribute", 'memberOf'
  groupMembershipFilter = loadConfigValue "group_membership_filter", 'member={0}'
  groupMembershipSearchMethod = loadConfigValue "group_membership_search_method", 'attribute' # filter | attribute
  rolesToInclude = loadConfigValue "roles_to_include", undefined, ((value) =>
    if value != '' then value.toLowerCase().split(',')), undefined
  useOnlyListenerRoles = loadConfigValue "use_only_listener_roles", false, ((value) =>
    value == true or value == 'true')
  userNameRewriteRule = loadConfigValue "username_rewrite_rule", undefined, (value) =>
    RegExp(value)

  baseDn = loadConfigValue "base_dn", "dc=example,dc=com"

  ldapUserNameAttribute = loadConfigValue "ldap_user_attribute", "cn"
  hubotUserNameAttribute = loadConfigValue "hubot_user_attribute", "name"
  groupNameAttribute = loadConfigValue "ldap_group_attribute", "cn"
  roomNameAttribute = loadConfigValue 'room_attribute', undefined
  roomSearchTree = loadConfigValue 'room_search_tree', undefined
  refreshTime = loadConfigValue "refresh_time", 21600000

  robot.logger.info "Starting ldap search with ldapURL: #{ldapHost}, bindDn: #{bindDn},
    userSearchFilter: #{userSearchFilter}, groupMembershipFilter: #{groupMembershipFilter},
    groupMembershipAttribute: #{groupMembershipAttribute}, groupMembershipSearchMethod: #{groupMembershipSearchMethod},
    rolesToInclude: #{rolesToInclude}, useOnlyListenerRoles: #{useOnlyListenerRoles}, baseDn: #{baseDn},
    ldapUserNameAttribute: #{ldapUserNameAttribute}, hubotUserNameAttribute: #{hubotUserNameAttribute},
    groupNameAttribute: #{groupNameAttribute}, userNameRewriteRule: #{userNameRewriteRule}, roomNameAttribute:
    #{roomNameAttribute}, roomSearchTree: #{roomSearchTree}"

  if !useOnlyListenerRoles and rolesToInclude
    wildcardExp = /.*\*.*/
    rolesToInclude = rolesToInclude.map (role) =>
      if role.match(wildcardExp) then role.replace /\*/g, '.*' else role
    rolesToInclude = new RegExp "^.*(#{rolesToInclude.join('|')}).*$"

  ensureConnected = ->
    if !client or client.destroyed
      robot.logger.debug("Creating ldap client")
      client = LDAP.createClient {
        url: ldapHost,
        bindDN: bindDn,
        bindCredentials: bindPassword
      }
    else unless client.connected
      robot.logger.debug("Reconnecting ldap")
      client.connect()

  getDnForUser = (userId, user) ->
    if userNameRewriteRule
      extractedUid = userId.match(userNameRewriteRule)
      if extractedUid and extractedUid[1]
        userId = extractedUid[1]
      else
        robot.logger.warning("User with #{hubotUserNameAttribute} '#{userId}' does not match userNameRewrite Rule.")
    dnSearch(getUserFilter(userId)).then (value) -> { user: user, dn: value }

  getUserFilter = (userId)->
    userSearchFilter.replace(/\{0\}/g, userId)

  dnSearch = (filter) ->
    opts = {
      filter: filter
      scope: 'sub',
      attributes: [
        dnAttributeName
      ],
      sizeLimit: 1
    }
    executeSearch(opts).then (value) ->
      if not value or value.length == 0
        return
      else if value[0] and value[0].objectName
        ret = value[0].objectName.toString().replace(/, /g, ',')
        ret

  getGroupRoomNamesByDn = (dns) ->
    getGroupAttributesByDn(dns, roomNameAttribute)

  getGroupNamesByDn = (dns) ->
    getGroupAttributesByDn(dns, groupNameAttribute)

  getGroupAttributesByDn = (dns, attribute) ->
    filter = dns.map (dn) -> "(#{dnAttributeName}=#{dn})"
    filter = "(|#{filter.join('')})"
    opts = {
      filter: filter
      scope: 'sub'
      sizeLimit: dns.length
      attributes: [
        attribute
      ]
    }
    executeSearch(opts).then (entries) ->
      entries.map (value) -> value.attributes[0].vals[0].toString()

  getGroupsDNsForUser = (user) ->
    if groupMembershipSearchMethod == 'attribute'
      filter = "(#{dnAttributeName}=#{user.dn})"
      attribute = groupMembershipAttribute
    else
      filter = groupMembershipFilter.replace(/\{0\}/g, user.dn)
      attribute = dnAttributeName

    robot.logger.debug "Getting groups DNs for user: #{user.dn}, filter = #{filter}, attribute = #{attribute}"
    opts = {
      filter: filter
      scope: 'sub'
      sizeLimit: 200
      attributes: [
        attribute
      ]
    }
    executeSearch(opts).then (value) ->
      _.flattenDeep value.map (entry) -> entry.attributes[0].vals.map (v) -> v.toString()

  discoverRoomNames = () ->
    opts = {
      scope: 'sub'
      sizeLimit: 200
      attributes: [
        roomNameAttribute
      ]
    }
    executeSearch(opts, roomSearchTree).then (entries) ->
      rooms = _.flattenDeep entries.map (entry) ->
        if entry.attributes.length > 0
          return entry.attributes[0].vals.map (v) -> v.toString()
        undefined
      rooms.filter(Boolean)

  executeSearch = (opts, searchDn=undefined) ->
    new Promise.Promise (resolve, reject) ->
      ensureConnected()
      searchDn = searchDn or baseDn
      client.search searchDn, opts, (err, res) ->
        arr = []
        if err
          reject err
        res.on 'searchEntry', (entry) ->
          arr.push entry
        res.on 'error', (err) ->
          reject err
        res.on 'end', (result) ->
          resolve arr

  loadListeners = (isOneTimeRequest, refreshUserDn=false, only_userId=undefined) ->
    setTimeout(loadListeners, refreshTime) unless isOneTimeRequest
    if !isOneTimeRequest and roomNameAttribute and roomSearchTree and robot.adapter.newRoom and robot.adapter.resolveRoom
      robot.logger.info('Discovering room names in LDAP')
      discoverRoomNames()
        .then (rooms) ->
          robot.logger.debug("Found Room names in ldap: #{rooms}")
          rooms
        .each (room) ->
          robot.adapter.resolveRoom(room)
            .then (roomId) ->
              robot.logger.debug("Room #{room} (#{roomId}) already exists.")
            .catch (data) ->
              robot.adapter.newRoom(data.room, false)
        .then () ->
          robot.logger.debug('Finished discovering room names')
        .catch (err) ->
          robot.logger.error('Error during room name discovery:', err)

    robot.logger.info "Loading users and roles from LDAP" unless only_userId
    listenerRoles = loadListenerRoles().map (e) -> e.toLowerCase()
    promises = []
    users = undefined
    if only_userId
      users = [robot.brain.userForId(only_userId)]
    else
      users = robot.brain.users()

    for userId in Object.keys users
      user = users[userId]
      userAttr = user[hubotUserNameAttribute]
      if userAttr
        if user.dn and !refreshUserDn
          promises.push new Promise.Promise (resolve) -> resolve {user: user}
        else
          promises.push getDnForUser(userAttr, user)

    promises.forEach (promise) ->
      promise.then (entry) ->
        if entry.dn
          entry.user.dn = entry.dn
          robot.logger.debug "Found DN for user #{entry.user.name}, DN: #{entry.user.dn}"
        if not entry.user.dn
          throw new Error("User #{entry.user.name} does not have a dn, skipping")
        entry.user
      .then (user) ->
        getGroupsDNsForUser(user).then (groupDns) ->
          filterRoles = if useOnlyListenerRoles then new RegExp "^.*(?:#{listenerRoles.join('|')}).*$" else rolesToInclude
          if filterRoles
            groupDns = groupDns.filter (e) -> e.toLowerCase().match(filterRoles)
          {user: user, groupDns: groupDns}
      .then (entry) ->
        getGroupNamesByDn(entry.groupDns).then (groupNames) ->
          groupNames = _.sortBy(groupNames)
          if groupNames.length > 0
            robot.logger.debug("Roles for #{entry.user.name} are #{groupNames}.")
          else
            robot.logger.debug("#{entry.user.name} has no roles.")
          entry.groupNames = groupNames
          entry
      .then (entry) ->
        if roomNameAttribute
          getGroupRoomNamesByDn(entry.groupDns).then (roomNames) ->
            roomNames = _.sortBy(roomNames)
            if roomNames.length > 0
              robot.logger.debug("Rooms for #{entry.user.name} are #{roomNames}.")
            else
              robot.logger.debug("#{entry.user.name} has no rooms.")
            entry.rooms = roomNames.map (e) -> e.replace /\ /g, '_'
            entry
        else
          entry
      .then (entry) ->
          brainUser = robot.brain.userForId entry.user.id
          brainUser.roles = entry.groupNames
          brainUser.dn = entry.user.dn
          if entry.rooms
            brainUser.rooms = entry.rooms
          else
            delete brainUser.rooms

          robot.brain.save()
      .catch (err) ->
        robot.logger.error "Error while getting user groups", err

    robot.logger.info "Users and roles were loaded from LDAP" unless only_userId
    Promise.all(promises)


  loadListenerRoles = () ->
    rolesToSearch = []
    for listener in robot.listeners
      roles = listener.options?.roles or []
      roles = [roles] if typeof roles is 'string'
      for role in roles
        if role not in rolesToSearch
          rolesToSearch.push role
    rolesToSearch

  class Auth
    loadSingle: (userId) ->
      loadListeners(true, false, userId)

    hasRole: (user, roles) ->
      userRoles = @userRoles(user)
      if userRoles?
        roles = [roles] if typeof roles is 'string'
        for role in roles
          return true if role in userRoles
      return false

    usersWithRole: (role) ->
      users = []
      for own key, user of robot.brain.data.users
        if @hasRole(user, role)
          users.push(user.name)
      users

    userRoles: (user) ->
      if user.roles?
        return user.roles
      return []

  robot.auth = new Auth

  robot.brain.on 'loaded', ->
    loadListeners()

  robot.respond /refresh roles(!)?/i, (msg) ->
    loadListeners(true, msg.match[1] == '!')

  robot.respond /what roles? do(es)? @?(.+) have\?*$/i, (msg) ->
    name = msg.match[2].trim()
    if name.toLowerCase() is 'i' then name = msg.message.user.name
    user = robot.brain.usersForFuzzyName(name) or {name: name}
    if user and user.length > 0 then user = user[0]
    return msg.reply "#{name} does not exist" unless user?
    userRoles = robot.auth.userRoles(user)

    if userRoles.length == 0
      msg.reply "#{name} has no roles."
    else
      msg.reply "#{user.name} has the following roles: #{userRoles.join(', ')}."

  robot.respond /who has (["'\w: -_]+) role\?*$/i, (msg) ->
    role = msg.match[1]
    userNames = robot.auth.usersWithRole(role) if role?

    if userNames.length > 0
      msg.reply "The following people have the '#{role}' role: #{_.sortBy(userNames).join(', ')}"
    else
      msg.reply "There are no people that have the '#{role}' role."
