# Description
#   Delegate authorization for Hubot user actions to LDAP
#
# Configuration:
#   HUBOT_LDAP_AUTH_HOST - the URL to the LDAP server
#   HUBOT_LDAP_AUTH_BIND_DN - the bind DN to authenticate with
#   HUBOT_LDAP_AUTH_BIND_PASSWORD - the bind password to authenticate with
#   HUBOT_LDAP_AUTH_USER_SEARCH_FILTER - the ldap filter search for a specific user - e.g. 'cn={0}' where '{0}' will be replaced by the hubot user attribute
#   HUBOT_LDAP_AUTH_GROUP_MEMBERSHIP_ATTRIBUTE - the member attribute within the user object
#   HUBOT_LDAP_AUTH_GROUP_MEMBERSHIP_FILTER - the membership filter to find groups based on user DN - e.g. 'member={0}' where '{0}' will be replaced by user DN
#   HUBOT_LDAP_AUTH_GROUP_MEMBERSHIP_SEARCH_METHOD - (filter | attribute) - how to find groups belong to users
#   HUBOT_LDAP_AUTH_ROLES_TO_INCLUDE - comma separated group names that will be used as roles, all the rest of the groups will be filtered out
#   HUBOT_LDAP_AUTH_USE_ONLY_LISTENER_ROLES - if true, groups will only be filtered by all listener options and ROLES_TO_INCLUDE will be ignored
#   HUBOT_LDAP_AUTH_SEARCH_BASE_DN - search DN to start finding users and groups within the ldap directory
#   HUBOT_LDAP_AUTH_LDAP_USER_ATTRIBUTE - the ldap attribute to match hubot users within the ldap directory
#   HUBOT_LDAP_AUTH_HUBOT_USER_ATTRIBUTE - the hubot user attribute to search for a user within the ldap directory
#   HUBOT_LDAP_AUTH_GROUP_LDAP_ATTRIBUTE - the ldap attribute of a group that will be used as role name
#   HUBOT_LDAP_AUTH_LDAP_REFRESH_TIME - time in millisecods to refresh the roles and users
#   HUBOT_LDAP_AUTH_DN_ATTRIBUTE_NAME - the dn attribute name, used for queries by DN. In ActiveDirectory should be distinguishedName
#   HUBOT_LDAP_AUTH_USER_ATTRIBUTE_REWRITE_RULE - regex for rewriting the hubot username to the one used in ldap - e.g. '@(.+):matrix.org' where the first capturing group will be used as username. No subsitution if omitted
#
# Commands:
#   hubot what roles does <user> have - Find out what roles a user has
#   hubot what roles do I have - Find out what roles you have
#   hubot refreh roles
#   hubot who has <roleName> role
#
# Notes:
#   * returns bool true or false
#

_ = require 'lodash'
LDAP = require 'ldapjs'
deferred = require 'deferred'
config = require 'config'

ENV_PREFIX = "HUBOT_LDAP_AUTH"
JSON_PREFIX = "ldap_auth"

module.exports = (inputRobot) ->
  robot = inputRobot

  loadConfigValue = (name, defaultValue, func...) ->
    result = process.env["#{ENV_PREFIX}_#{name.toUpperCase()}"]
    if result
      return if func.length == 0 then result else func[0] result

    if config.has("#{JSON_PREFIX}.#{name}")
      result = config.get("#{JSON_PREFIX}.#{name}")
      return if func.length == 0 or func[func.length - 1] == undefined then result else func[func.length - 1] result

    defaultValue

  ldapHost = loadConfigValue "host"
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

  ldapUserNameAttribute = loadConfigValue "user_ldap_attribute", "cn"
  hubotUserNameAttribute = loadConfigValue "user_hubot_attribute", "name"
  groupNameAttribute = loadConfigValue "group_ldap_attribute", "cn"
  ldapRefreshTime = loadConfigValue "ldap_refresh_time", 21600000

  robot.logger.info "Starting ldap search with ldapURL: #{ldapHost}, bindDn: #{bindDn}, userSearchFilter: #{userSearchFilter},
  groupMembershipFilter: #{groupMembershipFilter}, groupMembershipAttribute: #{groupMembershipAttribute}, groupMembershipSearchMethod: #{groupMembershipSearchMethod},
    rolesToInclude: #{rolesToInclude}, useOnlyListenerRoles: #{useOnlyListenerRoles}, baseDn: #{baseDn},
    ldapUserNameAttribute: #{ldapUserNameAttribute}, hubotUserNameAttribute: #{hubotUserNameAttribute}, groupNameAttribute: #{groupNameAttribute}, userNameRewriteRule: #{userNameRewriteRule}"

  if !useOnlyListenerRoles and rolesToInclude
    wildcardExp = /.*\*.*/
    rolesToInclude = rolesToInclude.map (role) =>
      if role.match(wildcardExp) then role.replace /\*/g, '.*' else role
    rolesToInclude = new RegExp "^#{rolesToInclude.join('|')}$"


  client = LDAP.createClient {
    url: ldapHost,
    bindDN: bindDn,
    bindCredentials: bindPassword
  }

  getDnForUser = (userId, user) ->
    if userNameRewriteRule
      userId = userId.match(userNameRewriteRule)[1]
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

  getGroupNamesByDn = (dns) ->
    filter = dns.map (dn) -> "(#{dnAttributeName}=#{dn})"
    filter = "(|#{filter.join('')})"
    opts = {
      filter: filter
      scope: 'sub'
      sizeLimit: dns.length
      attributes: [
        groupNameAttribute
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

  executeSearch = (opts) ->
    def = deferred()
    client.search baseDn, opts, (err, res) ->
      arr = []
      if err
        def.reject err
      res.on 'searchEntry', (entry) ->
        arr.push entry
      res.on 'error', (err) ->
        def.reject err
      res.on 'end', (result) ->
        def.resolve arr
    def.promise

  loadListeners = (isOneTimeRequest) ->
    if !isOneTimeRequest
      setTimeout ->
        loadListeners()
      , ldapRefreshTime
    robot.logger.info "Loading users and roles from LDAP"
    listenerRoles = loadListenerRoles()
      .map (e) -> e.toLowerCase()
    promises = []
    users = robot.brain.users()
    def = deferred()
    for userId in Object.keys users
      user = users[userId]
      userAttr = user[hubotUserNameAttribute]
      if userAttr
        promises.push((if user.dn then (def.resolve { user: user }; def.promise) else getDnForUser(userAttr, user)))

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
          {user: user, groupDns: groupDns}
      .then (entry) ->
        getGroupNamesByDn(entry.groupDns).then (groupNames) ->
          {user: entry.user, groupNames: groupNames}
      .then (entry) ->
        groupNames = entry.groupNames
        robot.logger.debug "groupNames for #{entry.user.name} are #{groupNames}"
        filterRoles = if useOnlyListenerRoles then new RegExp "^#{listenerRoles.join('|')}$" else rolesToInclude
        if filterRoles
          groupNames = groupNames.filter (e) -> e.toLowerCase().match(filterRoles)
        robot.logger.debug "groupNames for #{entry.user.name} are #{groupNames} - after filter"

        groupNames = _.sortBy(groupNames)
        brainUser = robot.brain.userForId entry.user.id
        brainUser.roles = groupNames
        brainUser.dn = entry.user.dn
        robot.brain.save()

      .catch (err) ->
        robot.logger.error "Error while getting user groups", err

    robot.logger.info "Users and roles were loaded from LDAP"


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

  robot.respond /refresh roles/i, (msg) ->
    loadListeners(true)

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
