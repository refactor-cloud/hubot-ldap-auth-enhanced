# hubot-ldap-auth-enhanced

[![npm version](https://badge.fury.io/js/hubot-ldap-auth-enhanced.svg)](https://badge.fury.io/js/hubot-ldap-auth-enhanced)

Enhanced version for Hubot command authentication for ldap.

Original idea by [jmcshane](https://github.com/jmcshane).

This module is derived from the [hubot-auth](https://github.com/hubot-scripts/hubot-auth) module and it delegates the 
main functions of authorization to an LDAP server using the [ldapjs](http://ldapjs.org/client.html) LDAP client.  In 
the implementation, it is meant to be a drop in replacement for the existing module so that the other integrations that 
exist around hubot-auth can continue to function properly.  All modifying actions have been removed from the auth client 
so that the LDAP server can act as a service providing authorization details to Hubot, rather than providing Hubot 
ability to do such modifications. Theoretically, this would be a separate script to do such an integration, but it is 
not in the scope of this module.

Starting with the startup of the bot, known DNs for known users are searched in ldap and - if found - roles are 
extracted. The roles are refreshed periodically, specified by ```refresh_time```. To force the refresh of the user DNs, 
one would have to issue a manual request to hubot (```hubot refresh roles!```). Mind the '!' at the end of the command.

If unique user ids in ldap differ from these known by hubot, a substitution can be specified with a regex. The first 
capturing group is representative of the username in ldap.
```
# @exampleUser:matrix.com -> exampleUser

@(.*):matrix.org
```

# Configuration
The environment variables are prefixed with 'HUBOT_LDAP_AUTH_'. (e.g. HUBOT_LDAP_AUTH_HOST)

The json config values are located below the key 'ldap_auth' and are all lowercase.

Variable | Default | Description
--- | --- | ---
HOST | ldap://127.0.0.1:389  | the address of the LDAP server
BIND_DN |  | the bind DN to authenticate with
BIND_PASSWORD |   | the bind password to authenticate with
USER_SEARCH_FILTER | cn={0} | the ldap filter search for a specific user - e.g. 'cn={0}' where '{0}' will be replaced by the hubot user attribute
GROUP_MEMBERSHIP_ATTRIBUTE | memberOf | the member attribute within the user object
GROUP_MEMBERSHIP_FILTER | member={0} | the membership filter to find groups based on user DN - e.g. 'member={0}' where '{0}' will be replaced by user DN
GROUP_MEMBERSHIP_SEARCH_METHOD | attribute | (filter / attribute) how to find groups belong to users
ROLES_TO_INCLUDE |   | comma separated group names that will be used as roles, all the rest of the groups will be filtered out. Json datatype needs to be array.
USE_ONLY_LISTENER_ROLES | false | if true, groups will only be filtered by all listener options and ROLES_TO_INCLUDE will be ignored
BASE_DN | dc=example,dc=com | search DN to start finding users and groups within the ldap directory
LDAP_USER_ATTRIBUTE | cn | the ldap attribute to match hubot users within the ldap directory
HUBOT_USER_ATTRIBUTE | name | the hubot user attribute to search for a user within the ldap directory
LDAP_GROUP_ATTRIBUTE | cn | the ldap attribute of a group that will be used as role name
REFRESH_TIME | 21600000 | time in millisecods to refresh the roles and users
DN_ATTRIBUTE_NAME | dn | the dn attribute name, used for queries by DN. In ActiveDirectory should be distinguishedName
USERNAME_REWRITE_RULE |   | regex for rewriting the hubot username to the one used in ldap - e.g. '@(.+):matrix.org' where the first capturing group will be used as username. No subsitution if omitted


# Commands

* hubot what roles does \<user\> have - Find out what roles a user has
* hubot what roles do I have - Find out what roles you have
* hubot refresh roles
* hubot refresh roles! - Refresh also already known user DNs
* hubot who has \<roleName\> role

## Integration with Hubot

This script is meant to be used with the [hubot-auth-middleware](https://github.com/HelloFax/hubot-auth-middleware) 
project which uses the auth plugin in Hubot to determine whether a user can take a particular action. See the 
[README.md](https://github.com/HelloFax/hubot-auth-middleware/blob/master/README.md) of that project for more details 
on configuring roles for user actions.

# Installation

In order to set up this plugin, first install it in the project:

```
npm install hubot-ldap-auth-enhanced --save
```

Then, add the script to the `external-scripts.json` file:

```json
[
    "hubot-ldap-auth-enhanced"
]
```

Optionally, add configuration variables to the file ```config/default.json```:
```json
{
  "ldap_auth": {
    "bind_dn": "cn=userReader,dc=example,dc=com",
    "bind_password": "superSecretPassword"
  }
}
```