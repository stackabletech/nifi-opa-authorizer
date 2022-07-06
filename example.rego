package app.rbac

import future.keywords.in

# By default, deny requests.
default allow = false

# Allow admins to do anything.
allow {
	user_is_admin
}

get_groups = groups {
   groups = data.user_roles[input.user]
}


# Allow the action if the user is granted permission to perform the action.
allow {
	# Find grants for the user.
	some grant
	user_is_granted[grant]

	# Check if the grant permits the action.
	input.action == grant.action
	input.type == grant.type
}

# user_is_admin is true if...
user_is_admin {
	# "admin" is among the user's roles as per data.user_roles
	"admin" in data.user_roles[input.user]
}

# user_is_granted is a set of grants for the user identified in the request.
# The `grant` will be contained if the set `user_is_granted` for every...
user_is_granted[grant] {
	# `role` assigned an element of the user_roles for this user...
	some role in data.user_roles[input.user]

	# `grant` assigned a single grant from the grants list for 'role'...
	some grant in data.role_grants[role]
}

data := {
    "role_grants": {
        "billing": [
            {
                "action": "read",
                "type": "finance"
            },
            {
                "action": "update",
                "type": "finance"
            }
        ],
        "customer": [
            {
                "action": "read",
                "type": "dog"
            },
            {
                "action": "read",
                "type": "cat"
            },
            {
                "action": "adopt",
                "type": "dog"
            },
            {
                "action": "adopt",
                "type": "cat"
            }
        ],
        "employee": [
            {
                "action": "read",
                "type": "dog"
            },
            {
                "action": "read",
                "type": "cat"
            },
            {
                "action": "update",
                "type": "dog"
            },
            {
                "action": "update",
                "type": "cat"
            }
        ]
    },
    "user_roles": {
        "alice": [
            "admin"
        ],
        "bob": [
            "employee",
            "billing"
        ],
        "eve": [
            "customer"
        ]
    }
}
