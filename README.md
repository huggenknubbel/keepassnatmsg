[![Main workflow](https://github.com/huggenknubbel/keepassnatmsg/actions/workflows/workflow.yml/badge.svg)](https://github.com/huggenknubbel/keepassnatmsg/actions/workflows/workflow.yml)

> This is a maintained fork of [smorks/keepassnatmsg](https://github.com/smorks/keepassnatmsg), which is no longer developed. It adds passkey support compatible with KeePassXC and keeps dependencies up to date. See [Changes compared to the original](#changes-compared-to-the-original).

# KeePassNatMsg

is a plugin for KeePass 2.x and provides a secure means of exposing KeePass credentials to a browser via [Native Messaging](https://developer.mozilla.org/en-US/Add-ons/WebExtensions/Native_messaging).

It is based on [KeePassHttp](https://github.com/pfn/keepasshttp).

This plugin is primarily intended for use with the [keepassxc-browser](https://github.com/keepassxreboot/keepassxc-browser) browser extension.

## Features
 * returns all matching entries for a given URL
 * updates entries
 * secure exchange of entries
 * notifies user if entries are delivered
 * user can allow or deny access to single entries
 * works only if the database is unlocked
 * request for unlocking the database if it is locked while connecting
 * searches in all opened databases (if user activates this feature)
 * Whenever events occur, the user is prompted either by tray notification or requesting interaction (allow/deny/remember).
 * passkeys, stored in the same `KPEX_PASSKEY_*` fields as KeePassXC, so they work in both (see [Passkeys](#passkeys))

## Changes compared to the original

The original KeePassNatMsg 2.0.17 was released in January 2024. This fork adds:

 * **Passkeys** (`passkeys-register` and `passkeys-get`), compatible with KeePassXC's implementation. A KeePass database can be used with KeePass on one machine and KeePassXC on another, passkeys included.
 * **Password generator** works again with current keepassxc-browser versions ([smorks/keepassnatmsg#118](https://github.com/smorks/keepassnatmsg/issues/118)). The plugin now reports KeePassXC 2.7.10 to the extension.
 * **Group name** is returned with each login, so the extension no longer shows "undefined" ([smorks/keepassnatmsg#121](https://github.com/smorks/keepassnatmsg/issues/121)).
 * **Port numbers**: an entry URL with an explicit port only matches that port, like in KeePassXC ([smorks/keepassnatmsg#88](https://github.com/smorks/keepassnatmsg/issues/88)).
 * **Dependencies**: Newtonsoft.Json 13.0.4 (fixes CVE-2024-21907), BouncyCastle 2.7.0 for the passkey cryptography, .NET Framework 4.8.
 * **Builds and releases** run again on current GitHub runners.

### AI assistance

This fork was partly developed with AI assistance.

## System requirements
 * KeePass 2.x (tested with 2.61)
 * For Windows: .NET Framework 4.8 or higher
 * For Linux: Mono 6.8 or higher
 * For Mac: Mono 6.8 or higher (untested)

## Installation

 1. Download the latest [KeePassNatMsg](https://github.com/huggenknubbel/keepassnatmsg/releases) release (`KeePassNatMsg-<version>-binaries.zip` or `KeePassNatMsg.plgx`)
 2. Unzip it into the KeePass\Plugins directory (or copy the `.plgx` file there). Remove older versions of KeePassNatMsg from that directory first.
	* No administrator rights are needed when using the portable version of KeePass in your user directory. The native messaging host is registered for the current user only.
	* default directory in Ubuntu14.04: /usr/lib/keepass2/
	* default directory in Arch: /usr/share/keepass
 3. On linux systems you maybe need to install mono-complete: `$ apt-get install mono-complete` (in Debian it should be enough to install the packages libmono-system-runtime-serialization4.0-cil and libmono-posix2.0-cil). Without libmono-system-runtime-serialization4.0-cil the plugin loads, but never answers the browser extension.
 * Tips to run KeePassNatMsg on lastest KeePass 2.31: install packages
 	`sudo apt-get install libmono-system-xml-linq4.0-cil libmono-system-data-datasetextensions4.0-cil libmono-system-runtime-serialization4.0-cil mono-mcs`
 4. Restart KeePass
 5. Go to Tools -> KeePassNatMsg Options
 6. Click on "Install/Update Native Messaging Host", wait for message telling you it was installed.
 7. Install the [KeePassXC-Browser](https://github.com/keepassxreboot/keepassxc-browser) extension for your browser, and Connect to the database from within the extension.

#### Package managers

The [Chocolatey package](https://community.chocolatey.org/packages/keepass-plugin-keepassnatmsg) and the [AUR package](https://aur.archlinux.org/packages/keepass-natmsg/) install the original KeePassNatMsg, not this fork. They don't include passkey support.

```
choco install keepass-plugin-keepassnatmsg
```

To upgrade the original package:

```
choco install keepass-plugin-keepassnatmsg
```

```
choco upgrade keepass-plugin-keepassnatmsg
```

### KeePassNatMsg on Linux and Mac

KeePass needs Mono. You can find detailed [installation instructions on the official page of KeePass](http://keepass.info/help/v2/setup.html#mono).

## Configuration and Options

KeePassNatMsg works out-of-the-box. You don't have to explicitly configure it.

 * KeePassNatMsg stores shared public keys in "KeePassNatMsg Settings" in the root group of a password database.
 * Password entries saved by KeePassNatMsg are stored in a new group named "KeePassNatMsg Passwords" within the password database.
 * Remembered Allow/Deny settings are stored as JSON in custom string fields within the individual password entry in the database.

### Settings in KeePassNatMsg options.

You can open the options dialog with menu: Tools > KeePassNatMsg Options

![KeePassNatMsg Options Menu](documentation/images/menu.png)

The options dialog will appear:

![KeePassNatMsg Options Dialog](documentation/images/options-general.png)

#### General tab

1. show a notification balloon whenever entries are delivered to the inquirer.
2. returns only the best matching entries for the given url, otherwise all entries for a domain are send.
  - e.g. of two entries with the URLs http://example.org and http://example.org/, only the second one will returned if the requested URL is http://example.org/index.html
3. if the active database in KeePass is locked, KeePassNatMsg sends a request to unlock the database. Now KeePass opens and the user has to enter the master password to unlock the database. Otherwise KeePassNatMsg tells the inquirer that the database is closed.
4. expired entries are ignored if enabled.
5. KeePassNatMsg returns only these entries which match the scheme of the given URL.
  - given URL: https://example.org --> scheme: https:// --> only entries whose URL starts with https://
6. sort found entries by username or title.
7. removes all stored permissions in the entries of the currently selected database.
8. Shows the status of the Native Messaging Host installations for the supported browsers, and the current Proxy version.
9. Installs or Updates the Native Messaging Host, and updates the Proxy if an update is available.

![KeePassNatMsg Options Advanced](documentation/images/options-advanced.png)

#### Advanced tab

10. KeePassNatMsg no longer asks for permissions to retrieve entries, it always allows access.
11. KeePassNatMsg no longer asks for permission to update an entry, it always allows updating them.
12. Choice of databases used for searches:
  - Use only the active database (default).
  - Use all open databases.
  - Always use a specific database.
13. When activated, it will search all string fields beginning with "URL".
14. if activated KeePassNatMsg also search for string fields which are defined in the found entries and start with "KPH: " (note the space after colon). __The string fields will be transferred to the client in alphabetical order__. You can set string fields in the tab _Advanced_ of an entry.
[<img src="documentation/images/advanced-string-fields.png" alt="advanced tab of an entry" width="300px" />](documentation/images/advanced-string-fields.png)
15. Override the version returned to KeePassXC-Browser
16. When a database is selected, KeePassNatMsg will always use the selected database to search for entries.
17. Use the same settings as KeePassXC. If checked, it will share all Allow/Deny lists and keys with KeePassXC.
  - ***It is strongly recommended that you make a backup of your database before using the Migrate Settings and Check for Legacy Config buttons.***
  - Migrate Settings: will migrate settings between KeePassNatMsg and KeePassXC.
  - Check for Legacy Config: will check to see if any legacy config exists in the current database, and migrate it to the new CustomData format.

![KeePassNatMsg Options Keys](documentation/images/options-keys.png)

#### Keys Tab

Will display all configured browser keys, and you can remove them as needed.

## Passkeys

KeePassNatMsg handles passkey requests from keepassxc-browser the same way KeePassXC does. Passkeys are stored in the `KPEX_PASSKEY_*` string fields of an entry, the format KeePassXC uses, so passkeys created in KeePass work in KeePassXC and the other way round. ES256, EdDSA and RS256 keys are supported.

To use passkeys, enable them in the keepassxc-browser settings (General tab, "Passkeys" card). The card is only shown when the extension is connected to KeePassNatMsg 2.1.0 or newer. If no passkey is found, the extension falls back to the browser's own passkey dialog unless the fallback option is turned off.

When a website registers a passkey, KeePassNatMsg asks where to store it:

 * entries matching the website that don't have a passkey yet are suggested; **Add to entry** stores the passkey there
 * the search field searches all entries of the database (KeePass search syntax), to add the passkey to any other entry
 * **Register new** creates a new entry in the group "KeePassXC-Browser Passkeys" (or the default passkey group set in keepassxc-browser)
 * if a passkey for the same user already exists, it is listed and can be replaced with **Update**

![Register a passkey: suggested entry](documentation/images/passkey-register-suggestion.png)

![Register a passkey: search for another entry](documentation/images/passkey-register-search.png)

When logging in, all passkeys for the website are listed:

![Log in with a passkey](documentation/images/passkey-authenticate.png)

The screenshots show KeePass on Linux (Mono); on Windows the dialogs use the native look.

## Tips and Tricks

### Support multiple URLs for one username + password
This is already implemented directly in KeePass.

1. Open the context menu of an entry by clicking right on it and select _Duplicate entry_:
[<img src="documentation/images/keepass-context-menu.png" alt="context-menu-entry" />](documentation/images/keepass-context-menu.png)

2. Check the option to use references for username and password:
[<img src="documentation/images/keepass-duplicate-entry-references.png" alt="mark checkbox references" width="300px" />](documentation/images/keepass-duplicate-entry-references.png)

3. You can change the title, URL and everything of the copied entry, but not the username and password. These fields contain a _Reference Key_ which refers to the _master entry_ you copied from.

### TOTP Field Support

KeePassNatMsg can use the built-in TOTP support in KeePass (since KeePass v2.47, [official docs](https://keepass.info/help/base/placeholders.html#otp)).

KeePassNatMsg can also use the existence of either KeeOtp (`otp`) or KeeTrayTOTP (`TOTP Seed`) string fields to detect when TOTP entries should be returned in credential requests.

## Troubleshooting

__First:__ If an error occurs it will be shown as notification in system tray or as message box in KeePass.

Otherwise please check if it could be an error of the client you are using. For keepassxc-browser issues you can [report an error here](https://github.com/keepassxreboot/keepassxc-browser/issues/).


If you are having problems with KeePassNatMsg, please [open an issue](https://github.com/huggenknubbel/keepassnatmsg/issues) and tell us at least the following information:
* operating system & version
* version of KeePass
* version of KeePassNatMsg
* error message (if available)
* used clients and their versions
* URLs on which the problem occur (if available)

## URL matching: How does it work?

KeePassNatMsg can receive 2 different URLs, called URL and SubmitURL.

CompareToUrl = SubmitURL if set, URL otherwise

For every entry, the [Levenshtein Distance](http://en.wikipedia.org/wiki/Levenshtein_distance) of his Entry-URL (or Title, if Entry-URL is not set) to the CompareToURL is calculated.

Only the Entries with the minimal distance are returned.

### Example:
Submit-Url: http://www.host.com/subdomain1/login

Entry-URL|Distance
---|---
http://www.host.com/|16
http://www.host.com/subdomain1|6
http://www.host.com/subdomain2|7

__Result:__ second entry is returned

## Protocol

- View [detailed protocol information](https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md).
