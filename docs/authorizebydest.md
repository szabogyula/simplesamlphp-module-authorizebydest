authorizebydest Module
======================

<!--
	This file is written in Markdown syntax.
	For more information about how to use the Markdown syntax, read here:
	http://daringfireball.net/projects/markdown/syntax
-->

  * Author: Gyula Szabó <gyufi@szabocsalad.com>
  * Package: SimpleSAMLphp

This module provides a user authorization filter based on destination and user attribute matching.


`authorizebydest:AuthorizeByDest`
: Authorize certain users based on destination and user attribute matching


`authorizebydest:AuthorizeByDest`
---------------------


Unauthorized users will be shown a 403 Forbidden page.

### `attribute` ###
The default action of the filter is to authorize only if an attribute match is found (default allow). When set to TRUE, this option reverses that rule and authorizes the user unless an attribute match is found (default deny), causing an unauthorized action.

Note: This option needs to be boolean (TRUE/FALSE) else it will be considered an attribute matching rule.

### `attribute_value` ###
Turn regex pattern matching on or off for the attribute values defined. For backwards compatibility, this option defaults to TRUE, but can be turned off by setting it to FALSE.

Note: This option needs to be boolean (TRUE/FALSE) else it will be considered an attribute matching rule.

### `destination_whitelist` ###
Array of sp entityids. The users with the attributes described above can access these SP-s and cant access other SPs.  

### `discriminant_attribute` ###
The attribute that hold the user ids.

### `discriminant_users` ###
The array of vaules (uids) of the discrimimnat users.


### Examples ###
To use this filter configure it in `metadata/saml20-idp-hosted.php`.

```php
'authproc' => [
    10 => [
        'class' => 'authorizebydest:AuthorizeByDest',
        'attribute'   =>  'eduPersonAffiliation',
        'attribute_value' => 'affiliate',
        'destination_whitelist' => [
            'https://intraweb.local',
            'https://webmail.local',
        ]
        'discriminant_attribute' => 'uid',
        'discriminant_users' => [
            'vip_1',
            'vip_2',
        ]
    ]
]
```

In this case the users with affiliate affiliation can access the intraweb and webmail but deny other else.

Discriminant users - uid vip_1 and vip_2 - not denied anywhere.

