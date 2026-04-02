# WebUI

WebUI is an RDK-B component that provides a device-local, browser-based management portal implemented primarily in PHP and served by `lighttpd` via FastCGI (`php-cgi`). It includes multiple major areas: a PHP C extension that exposes CCSP message bus data-model operations to PHP, a PHP API wrapper around that extension, and the UI implementation itself (pages, templates, JavaScript, CSS, and localization resources) organized under style/theme directories.

Within this repository, WebUI functionality is implemented across several top-level source folders. The CCSP data model integration is provided by the PHP extension under `source/CcspPhpExtension/` (implemented in `cosa.c`) and the PHP wrapper functions under `source/CcspPhpApi/` (for example, `ccspdm.php`). The server-rendered UI pages, common includes, JavaScript/CSS assets, and device-side webserver configuration scripts are organized under `source/Styles/` (with device/theme-specific subtrees such as `xb3/` and `xb6/`).

```mermaid
graph LR
    subgraph "External Systems"
        Browser["User Browser"]
    end

    subgraph "RDK-B Device"
        Lighttpd["lighttpd"]
        PhpCgi["php-cgi (FastCGI)"]
        Pages["WebUI PHP Pages<br>(Styles/*/code)"]

        subgraph "WebUI Data Model Access Layer"
            PhpApi["CcspPhpApi<br>(ccspdm.php)"]
            PhpExt["CcspPhpExtension<br>(cosa.so)"]
        end

        CCSPBus["CCSP Message Bus"]
        DataModelOwners["RDK-B Components exposing TR-181 Data Model"]
    end

    %% External connections
    Browser -->|HTTP/HTTPS| Lighttpd

    %% Web server to PHP runtime
    Lighttpd -->|FastCGI .php| PhpCgi
    PhpCgi --> Pages

    %% Data model access
    Pages -->|PHP calls| PhpApi
    PhpApi -->|Extension API| PhpExt
    PhpExt -->|CCSP message bus| CCSPBus
    CCSPBus -->|Get/Set TR-181| DataModelOwners

    classDef external fill:#fff3e0,stroke:#ef6c00,stroke-width:2px;
    classDef webui fill:#e3f2fd,stroke:#1976d2,stroke-width:3px;
    classDef rdkbComponent fill:#e8f5e8,stroke:#2e7d32,stroke-width:2px;
    classDef system fill:#fce4ec,stroke:#c2185b,stroke-width:2px;

    class Browser external;
    class Pages,PhpApi,PhpExt webui;
    class CCSPBus,DataModelOwners rdkbComponent;
    class Lighttpd,PhpCgi system;
```

**Key Features & Responsibilities**:

- **Local Web Management UI served by lighttpd**: The UI is composed of PHP pages (for example, `source/Styles/xb3/code/*.php`) designed to be served by `lighttpd` with a 404 handler redirecting to `index.php`, enabling a browser-based management portal.
- **CCSP data-model access from PHP via a C extension**: The PHP extension implemented in `source/CcspPhpExtension/cosa.c` exposes functions such as `DmExtGetStrsWithRootObj`, `DmExtSetStrsWithRootObj`, and `DmExtGetInstanceIds`, allowing PHP code to interact with CCSP/TR-181 parameters over the CCSP message bus.
- **PHP wrapper API over the extension**: `source/CcspPhpApi/ccspdm.php` provides PHP helper functions (`DmGetStrsWithRootObj`, `DmSetStrsWithRootObj`, `DmGetInstanceIds`, `DmAddObj`, `DmDelObj`) that call the underlying extension methods, encouraging UI code to use a consistent API layer.
- **Session, locale, and role-based access gating**: Common includes (for example, `source/Styles/xb3/code/includes/header.php`) start sessions, set locale based on `LANG`, enforce authentication via session variables (including a JWT flag path), and deny access to specific page groups depending on the logged-in user type.
- **Built-in request-hardening utilities**: Action handlers share validation utilities in `source/Styles/xb3/code/includes/actionHandlerUtility.php`, including strict input validation helpers (MAC, IP, port, URL patterns) and SSID naming constraints.
- **CSRF protection initialization**: Common includes and action handler utilities initialize a CSRF protection library via `csrfprotector_rdkb::init()` using `source/Styles/xb3/code/CSRF-Protector-PHP/libs/csrf/csrfprotector_rdkb.php` and its configuration under `source/Styles/xb3/code/CSRF-Protector-PHP/libs/config.php`.

## Design

WebUI follows a server-rendered PHP architecture where page rendering and most workflow logic live in PHP, while JavaScript is used for client-side form handling and AJAX requests to `actionHandler` endpoints. A shared header include (`includes/header.php`) bootstraps core concerns such as session management, locale initialization, CSRF library initialization, and access checks; a shared navigation include (`includes/nav.php`) computes menu visibility based on device state and partner identifiers; and shared utilities (`includes/utility.php`, `includes/actionHandlerUtility.php`) centralize data-model access helpers and validation logic.

For data access and configuration, the UI relies on CCSP/TR-181 parameter operations exposed into PHP. In the header, WebUI uses `DmExtGetStrsWithRootObj()` to retrieve multiple parameter values in a single call. Across the UI and handlers, `getStr()` and related functions (published from the `cosa.so` extension) are used to fetch device state and apply configuration changes. This design tightly couples the UI to the CCSP data model rather than a separate REST layer.

Northbound interaction is HTTP/HTTPS traffic from a browser to `lighttpd`. Southbound interaction is the PHP extension's communication to the CCSP message bus (and thereby to the underlying RDK-B components that own the TR-181 parameters). The webserver layer uses the `lighttpd` configuration and startup script under `source/Styles/xb3/config/`, where `lighttpd` is configured to route PHP through FastCGI and to use `/index.php` as the 404 handler.

### Operational Execution Model

Within this repository, the application does not implement its own threading primitives at the PHP layer. Instead, concurrency and isolation are shaped by the web server and the PHP runtime integration.

`source/Styles/xb3/config/lighttpd.conf` configures PHP execution via `mod_fastcgi` using a FastCGI backend that can spawn multiple `php-cgi` processes. Specifically, the `fastcgi.server` entry for `".php"` configures `max-procs` to `"2"` and a `bin-path` of `"/fss/gw/bin/php-cgi -c /fss/gw/etc/php.ini"`. Multiple PHP processes may execute requests concurrently, with per-request PHP state isolated at the process level except for shared external resources (for example, the CCSP message bus).

At the extension layer, `source/CcspPhpExtension/cosa.c` shows that the CCSP message bus handle is stored in a global `bus_handle` and is initialized lazily in `PHP_RINIT_FUNCTION(cosa)` when `bus_handle` is `NULL`. Within a given `php-cgi` process, the first request that uses the extension causes `CCSP_Message_Bus_Init(...)` and `CCSP_Message_Bus_Register_Path(...)` to be called, after which subsequent requests in the same process reuse the initialized bus handle.

A component diagram showing the WebUI’s internal structure and dependencies is given below:

```mermaid
graph LR
    subgraph "External Systems"
        Browser["User Browser"]
    end

    subgraph "RDK-B Device"
        Lighttpd["lighttpd"]
        PhpCgi["php-cgi (FastCGI)"]

        subgraph "WebUI (PHP)"
            Pages["PHP Pages<br>(Styles/*/code/*.php)"]
            Includes["Common Includes<br>(includes/header.php, nav.php, utility.php)"]
            Handlers["AJAX Action Handlers<br>(code/actionHandler/*.php)"]
            Csrf["CSRF Protector Library<br>(CSRF-Protector-PHP)"]
            Jwt["JWT Verification Helpers<br>(includes/jwt.php)"]
            Validators["Input Validation Helpers<br>(includes/actionHandlerUtility.php)"]
            PhpApi["CcspPhpApi<br>(CcspPhpApi/ccspdm.php)"]
            PhpExt["CcspPhpExtension<br>(cosa.so from cosa.c)"]
        end

        CCSPBus["CCSP Message Bus"]
        DataModelOwners["RDK-B Data Model Owners<br>(Components exposing TR-181)"]
    end

    %% External connections
    Browser -->|HTTP/HTTPS| Lighttpd

    %% Request handling path
    Lighttpd -->|FastCGI| PhpCgi
    PhpCgi --> Pages
    Pages --> Includes
    Pages --> Handlers

    %% Cross-cutting security utilities
    Includes --> Csrf
    Handlers --> Csrf
    Includes --> Jwt
    Handlers --> Validators

    %% Data model access
    Pages --> PhpApi
    Handlers --> PhpApi
    PhpApi --> PhpExt
    PhpExt --> CCSPBus
    CCSPBus --> DataModelOwners

    classDef external fill:#fff3e0,stroke:#ef6c00,stroke-width:2px;
    classDef webui fill:#e3f2fd,stroke:#1976d2,stroke-width:3px;
    classDef rdkbComponent fill:#e8f5e8,stroke:#2e7d32,stroke-width:2px;
    classDef system fill:#fce4ec,stroke:#c2185b,stroke-width:2px;

    class Browser external;
    class Pages,Includes,Handlers,Csrf,Jwt,Validators,PhpApi,PhpExt webui;
    class CCSPBus,DataModelOwners rdkbComponent;
    class Lighttpd,PhpCgi system;
```

### Prerequisites and Dependencies

**Build and Source Layout Prerequisites:**

This repository contains a PHP extension under `source/CcspPhpExtension/` (for example, `cosa.c` and `config.m4`), a PHP wrapper API under `source/CcspPhpApi/` (for example, `ccspdm.php`), and UI/page assets plus device-side configuration under `source/Styles/` (for example, `source/Styles/xb3/config/lighttpd.conf`, `source/Styles/xb3/config/php.ini`, and `source/Styles/xb3/config/webgui.sh`).

**Web Server Configuration:**

The `lighttpd` configuration at `source/Styles/xb3/config/lighttpd.conf` includes:
- `server.document-root = "/fss/gw" + "/usr/www/"`
- `server.error-handler-404 = "/index.php"`
- FastCGI mapping for `.php` with `php-cgi` launched using `-c /fss/gw/etc/php.ini`.

**PHP Configuration and Extension Loading:**

`source/Styles/xb3/config/php.ini` configures the PHP runtime to load the CCSP PHP extension by setting `extension_dir = "/fss/gw/usr/ccsp"` and `extension=cosa.so`. It also contains hardening-related settings such as `disable_functions = phpinfo`, `display_errors = Off`, `log_errors = On`, `allow_url_fopen = Off`, and `allow_url_include = Off`.

**PHP Extension Build Dependencies:**

`source/CcspPhpExtension/config.m4` shows the extension build checks for:
- `libccsp_common.so` in `$CCSP_COMMON_LIB`
- include paths under `$CCSP_DEP_HEADER`, `$CCSP_COMMON_SRC`, and `$CCSP_COMMON_BOARD_INC`
- libraries `crypto`, `ssl`, and `ccsp_common`.

Because these are referenced in the build configuration, they represent build-time requirements for compiling the PHP extension in environments where the CCSP common libraries and headers are available.

**Runtime Startup Script:**

`source/Styles/xb3/config/webgui.sh` is a device-side script that prepares runtime state and starts `lighttpd -f /etc/lighttpd.conf` with `LD_LIBRARY_PATH` including `/fss/gw/usr/ccsp`, implying runtime dependency on the extension and CCSP libraries being present at that path. The script also interacts with device utilities such as `syscfg`, `psmcli`, `sysevent`, and `dmcli` to read and set device state used for captive portal and other flows.

**Localization resources:**

`source/Styles/xb3/code/includes/header.php` uses gettext functions (`bindtextdomain`, `textdomain`) with `bindtextdomain($domain, 'locales')`, and the repository contains localization directories under `source/locales/`.

**Threading Model**

The repository does not provide an application-level threading model inside the PHP pages themselves. Operational concurrency is instead determined by the `lighttpd` + FastCGI configuration and by how the `php-cgi` processes load and use the CCSP PHP extension.

At the service-start boundary, `source/Styles/xb3/config/webgui.sh` implements a single-instance guard using a lock file (`/tmp/webgui.lock`) and a retry loop. This script-level locking ensures that only one orchestrator instance is responsible for starting `lighttpd` and generating configuration artifacts at a time; it does not serialize HTTP requests once the web server is running.

At the CCSP/PHP-extension boundary, `source/CcspPhpExtension/cosa.c` shows that the extension keeps a per-process global `bus_handle` and initializes it in `PHP_RINIT_FUNCTION(cosa)` when it is not yet set. This means CCSP message bus initialization and path registration happen once per `php-cgi` process (the first time a request triggers `RINIT` with `bus_handle == NULL`), and subsequent requests handled by the same process reuse the existing `bus_handle`. The extension calls `CCSP_Message_Bus_Exit(bus_handle)` in `PHP_MSHUTDOWN_FUNCTION(cosa)` when the process is shutting down.

### Component State Flow

**Initialization to Active State**

Based on `webgui.sh` and the `lighttpd` configuration, WebUI's lifecycle follows a device/service startup path that prepares runtime state and starts `lighttpd`, after which requests are served and routed to PHP pages and handlers.

`source/Styles/xb3/config/webgui.sh` shows several runtime preparation and gating steps before starting `lighttpd`, including creating and permissioning log files (for example `/rdklogs/logs/lighttpderror.log` and `/rdklogs/logs/webui.log`), ensuring only one instance runs at a time via `/tmp/webgui.lock`, killing any existing `lighttpd` process, and generating the pause-screen HTML via `/etc/pauseBlockGenerateHtml.sh` after copying common assets to `/tmp/pcontrol`.

Once started, the script exports `LD_LIBRARY_PATH=/fss/gw/usr/ccsp:$LD_LIBRARY_PATH` when launching `lighttpd`, which is consistent with the WebUI runtime requirement that the CCSP PHP extension (`cosa.so`) and its dependent shared libraries are found under `/fss/gw/usr/ccsp`.

```mermaid
sequenceDiagram
    autonumber
    participant System as Device Boot / Service Manager
    participant WebguiSh as webgui.sh
    participant Lighttpd as lighttpd
    participant PhpCgi as php-cgi (FastCGI)
    participant WebUI as WebUI PHP

    System->>WebguiSh: Start WebUI service/script
    Note right of WebguiSh: Create log files and set permissions<br>Single-instance lock via /tmp/webgui.lock<br>Generate pause screen HTML

    WebguiSh->>Lighttpd: Exec lighttpd -f /etc/lighttpd.conf (with LD_LIBRARY_PATH)
    Lighttpd->>PhpCgi: Spawn/connect FastCGI for .php
    Note right of Lighttpd: 404 handler routes to /index.php<br>Document root uses /fss/gw/usr/www<br>FastCGI backend uses php-cgi with /fss/gw/etc/php.ini

    PhpCgi->>WebUI: Execute requested PHP script
    Note right of WebUI: CSRF init, session_start, locale init<br>Access gating based on session

    WebguiSh-->>System: sysevent set webserver started<br>touch /tmp/webgui_initialized
```

**Per-Request Bootstrapping and State Initialization**

A typical page request initializes request context through shared includes, especially `source/Styles/xb3/code/includes/header.php`.

That header performs the following steps in order, all within the request’s PHP execution:

First, it includes the CSRF protector wrapper and calls `csrfprotector_rdkb::init()`.

Next, it calls `session_start()` and sets locale based on `getenv("LANG")`. If the session language is not set or differs from the current locale, it updates `LC_MESSAGES` and `LC_TIME` and configures gettext domains with `bindtextdomain($domain, 'locales')`, `bind_textdomain_codeset($domain, 'UTF-8')`, and `textdomain($domain)`, storing the selected locale in `$_SESSION['language']`.

It then enforces access gating. If `$_SESSION["loginuser"]` is not set, it checks `$_SESSION["JWT_VALID"]` and, when that flag is not present or not `true`, it returns a JavaScript alert and redirects to `home_loggedout.php` before exiting.

After access gating, it computes and stores key “mode” session state from TR-181 parameters using `DmExtGetStrsWithRootObj` and `getStr`:

It reads `Device.X_CISCO_COM_DeviceControl.LanManagementEntry.1.LanMode` and normalizes it to either `bridge-static` or `router` (defaulting to `router` when it is neither of those values), storing the result in `$_SESSION["lanMode"]`.

It reads `Device.X_CISCO_COM_DeviceControl.PowerSavingModeStatus` and normalizes it to `Enabled` or `Disabled` (defaulting to `Disabled` otherwise), storing the result in `$_SESSION["psmMode"]`.

It also reads branding and identification parameters such as `Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.RDKB_UIBranding.LocalUI.MSOLogoTitle`, `Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.RDKB_UIBranding.LocalUI.MSOLogo`, `Device.DeviceInfo.X_RDKCENTRAL-COM_Syndication.PartnerId`, and `Device.DeviceInfo.ModelName`, and defines `PREPAID` when the model name is `TG1682P`.

**Runtime State Changes and Feature Visibility**

The navigation module (`source/Styles/xb3/code/includes/nav.php`) uses both request/session state and live TR-181 values to decide which menu items are visible. It reads `PartnerId` and `ModelName` via `getStr`, and it uses `$_SESSION["lanMode"]` and `$_SESSION["loginuser"]` to hide groups of “Advanced” and “Parental Control” pages in bridge mode and to change the menu for `admin` versus `mso` users.

Action handlers also rely on session state to compute status. For example, `source/Styles/xb3/code/actionHandler/ajaxSet_userbar.php` uses `$_SESSION["lanMode"]` and `$_SESSION["psmMode"]` to influence computed connectivity status, and it persists derived status values back into the session (for example, `$_SESSION['sta_inet']`, `$_SESSION['sta_wifi']`, `$_SESSION['sta_moca']`, `$_SESSION['sta_fire']`).

Request processing both consumes and updates `$_SESSION` state, with additional device-state read-through via CCSP/TR-181 on each request as needed.

### Call Flow

**Initialization Call Flow**

```mermaid
sequenceDiagram
    participant Init as Service Startup
    participant Lighttpd as lighttpd
    participant PhpCgi as php-cgi
    participant Page as index.php

    Init->>Lighttpd: Start with lighttpd.conf
    Lighttpd->>PhpCgi: Configure FastCGI for .php
    Init->>Lighttpd: Ready to accept HTTP requests
    Lighttpd->>Page: Route / or 404 to /index.php
```

**Request Processing Call Flow**

The userbar status handler `source/Styles/xb3/code/actionHandler/ajaxSet_userbar.php` validates session state and retrieves device parameters via `getStr()` and `getInstanceIds()`.

```mermaid
sequenceDiagram
    participant Browser as Browser
    participant Lighttpd as lighttpd
    participant PhpCgi as php-cgi
    participant Handler as ajaxSet_userbar.php
    participant Cosa as cosa.so (PHP extension)
    participant CCSP as CCSP Message Bus

    Browser->>Lighttpd: HTTP request: actionHandler/ajaxSet_userbar.php
    Lighttpd->>PhpCgi: FastCGI dispatch
    PhpCgi->>Handler: Execute handler
    Handler->>Handler: Check session loginuser
    Handler->>Cosa: getStr(), getInstanceIds()
    Cosa->>CCSP: Get parameter values / instance IDs
    CCSP-->>Cosa: Return values
    Cosa-->>Handler: Return values to PHP
    Handler-->>Browser: JSON-encoded status/tips
```

## Internal Modules

WebUI’s repository structure provides clear module boundaries aligned to source folders and common include points.

| Module/Class | Description | Key Files |
|-------------|------------|-----------|
| UI Pages | Server-rendered PHP pages representing the management portal screens. Pages typically include shared header/nav/footer and call data-model functions to render current state. | `source/Styles/xb3/code/*.php`, `source/Styles/xb6/code/*.php` |
| Common Includes | Shared bootstrapping and UI infrastructure, including session initialization, locale, access control gates, and menu generation. | `source/Styles/xb3/code/includes/header.php`, `source/Styles/xb3/code/includes/nav.php`, `source/Styles/xb3/code/includes/utility.php` |
| Action Handlers | AJAX endpoints that validate input and apply configuration changes or return data for dynamic UI elements. | `source/Styles/xb3/code/actionHandler/*.php` |
| Action Handler Utilities | Shared input-validation utilities and helper functions used by action handlers; includes CSRF initialization. | `source/Styles/xb3/code/includes/actionHandlerUtility.php` |
| CSRF Protection Library | CSRF protection wrapper and configuration used by includes and handlers, initialized via `csrfprotector_rdkb::init()`. | `source/Styles/xb3/code/CSRF-Protector-PHP/libs/csrf/csrfprotector_rdkb.php`, `source/Styles/xb3/code/CSRF-Protector-PHP/libs/config.php` |
| JWT Verification Helpers | JWT verification utilities used by authentication/session flows (for example, referenced by `check.php`). | `source/Styles/xb3/code/includes/jwt.php` |
| CCSP PHP API Wrapper | Higher-level PHP API functions that delegate to extension functions for get/set/add/delete of objects/parameters. | `source/CcspPhpApi/ccspdm.php` |
| CCSP PHP Extension | C-based PHP extension exposing CCSP data-model operations to PHP. | `source/CcspPhpExtension/cosa.c`, `source/CcspPhpExtension/config.m4` |
| Server Configuration / Startup | Device-side webserver configuration and startup logic for `lighttpd` and PHP. | `source/Styles/xb3/config/lighttpd.conf`, `source/Styles/xb3/config/php.ini`, `source/Styles/xb3/config/webgui.sh` |

```mermaid
graph LR
    subgraph "WebUI"
        Pages["UI Pages (PHP)"]
        Includes["Common Includes"]
        Handlers["AJAX Action Handlers"]
        Validators["ActionHandler Utilities"]
        Csrf["CSRF Protector"]
        Jwt["JWT Helpers"]
        PhpApi["CCSP PHP API<br>(ccspdm.php)"]
        PhpExt["PHP Extension<br>(cosa.so)"]
    end

    Pages --> Includes
    Pages --> Handlers
    Handlers --> Validators
    Includes --> Csrf
    Validators --> Csrf
    Includes --> Jwt
    Pages --> PhpApi
    Handlers --> PhpApi
    PhpApi --> PhpExt

    classDef webui fill:#e3f2fd,stroke:#1976d2,stroke-width:3px;
    class Pages,Includes,Handlers,Validators,Csrf,Jwt,PhpApi,PhpExt webui;
```

## Component Interactions

WebUI interacts with several classes of "external" dependencies, but most interactions are device-local. The implementation shows heavy use of CCSP data-model access via the PHP extension (for example, `getStr`, `getInstanceIds`, and `DmExtGetStrsWithRootObj`) and device-side scripts that invoke platform CLIs (`dmcli`, `psmcli`, `syscfg`, `sysevent`) to manage system state during startup or captive portal enablement.

```mermaid
graph LR
    subgraph "External Systems"
        Browser["User Browser"]
    end

    subgraph "RDK-B Device"
        PlatformCLIs["Device CLIs<br>(syscfg, sysevent, dmcli, psmcli)"]
        Lighttpd["lighttpd"]
        WebUI["WebUI PHP"]
        CCSP["CCSP Message Bus"]
        DataModel["TR-181 Data Model Owners"]
    end

    %% External connections
    Browser -->|HTTP/HTTPS| Lighttpd

    %% Local runtime integration
    PlatformCLIs -->|configure/start server| Lighttpd
    Lighttpd -->|FastCGI| WebUI

    %% Data model access
    WebUI -->|get/set params| CCSP
    CCSP -->|Get/Set TR-181| DataModel

    classDef external fill:#fff3e0,stroke:#ef6c00,stroke-width:2px;
    classDef webui fill:#e3f2fd,stroke:#1976d2,stroke-width:3px;
    classDef rdkbComponent fill:#e8f5e8,stroke:#2e7d32,stroke-width:2px;
    classDef system fill:#fce4ec,stroke:#c2185b,stroke-width:2px;

    class Browser external;
    class WebUI webui;
    class CCSP,DataModel rdkbComponent;
    class Lighttpd,PlatformCLIs system;
```

### Interaction Matrix

| Target Component/Layer | Interaction Purpose | Key APIs/Endpoints |
|------------------------|-------------------|------------------|
| **Web Server Layer** | Serve PHP pages and route requests to FastCGI. | `source/Styles/xb3/config/lighttpd.conf` (`fastcgi.server` for `.php`, `server.error-handler-404 = "/index.php"`) |
| **PHP runtime configuration** | Configure PHP runtime behavior and load the CCSP PHP extension. | `source/Styles/xb3/config/php.ini` (`extension_dir`, `extension=cosa.so`) |
| **CCSP Data Model (via message bus)** | Read and write TR-181 parameters and table instances used by pages and handlers. | Extension functions published in `source/CcspPhpExtension/cosa.c` (for example, `DmExtGetStrsWithRootObj`, `DmExtSetStrsWithRootObj`, `DmExtGetInstanceIds`) and PHP wrapper in `source/CcspPhpApi/ccspdm.php` (`DmGetStrsWithRootObj`, `DmSetStrsWithRootObj`, `DmGetInstanceIds`) |
| **Session/auth and access gating** | Enforce login requirements and page access restrictions by role and device mode. | `source/Styles/xb3/code/includes/header.php`, `source/Styles/xb3/code/check.php` |
| **CSRF protection** | Initialize CSRF protection for UI pages and action handlers. | `csrfprotector_rdkb::init()` in `source/Styles/xb3/code/includes/header.php` and `source/Styles/xb3/code/includes/actionHandlerUtility.php`; config in `source/Styles/xb3/code/CSRF-Protector-PHP/libs/config.php` |
| **Device startup orchestration** | Prepare runtime state, logs, optional captive portal logic, and start `lighttpd`. | `source/Styles/xb3/config/webgui.sh` (starts `lighttpd -f /etc/lighttpd.conf`) |

**Events Published by WebUI:**

WebUI does not contain an explicit RBus event publication module. The principal mechanism for cross-component interaction is CCSP data-model access (get/set) rather than explicit event publishing from WebUI.

### IPC Flow Patterns

**Primary IPC Flow - Read/Compute Status for UI Elements:**

```mermaid
sequenceDiagram
    participant UI as WebUI Page (PHP)
    participant AH as Action Handler
    participant Ext as cosa.so
    participant Bus as CCSP Message Bus

    UI->>AH: AJAX request for status
    AH->>AH: Validate session
    AH->>Ext: getStr(), getInstanceIds()
    Ext->>Bus: GetParameterValues / GetInstances
    Bus-->>Ext: Values
    Ext-->>AH: Return to PHP
    AH-->>UI: JSON response
```

**Event Notification Flow:**

No explicit event-notification subsystem exists for WebUI. Dynamic updates are handled by browser-initiated AJAX calls to `actionHandler` endpoints, which then query state via CCSP data-model operations.

## Implementation Details

### Major HAL APIs Integration

No direct HAL API calls exist within the PHP code. Hardware and subsystem interactions are mediated through the CCSP data model (via the PHP extension) and through device-side command-line tools invoked by startup scripts (for example, `dmcli`, `syscfg`, `sysevent`, `psmcli`) rather than through linking to HAL libraries inside the WebUI application code.

### Key Implementation Logic

WebUI’s core logic is primarily organized around these patterns:

- **Session and access enforcement in shared includes**: `source/Styles/xb3/code/includes/header.php` starts a session, sets locale using `LANG`, performs access checks, and denies access if the session does not indicate a logged-in user or valid JWT session state. It also normalizes and stores device mode flags such as `lanMode` and `psmMode` into session variables after reading them via `DmExtGetStrsWithRootObj`.
- **Dynamic navigation based on device state and partner identity**: `source/Styles/xb3/code/includes/nav.php` reads partner and model identity (`PartnerId`, `ModelName`) and session mode (`lanMode`) to build the menu and conditionally hide pages in bridge mode or for specific user roles.
- **Input validation for action handlers**: `source/Styles/xb3/code/includes/actionHandlerUtility.php` provides validation helpers for printable character constraints, MAC and IP validation, port ranges, URL patterns (including IPv6 forms), and SSID naming constraints. These utilities are used by action handlers before applying changes.
- **Status computation and JSON serialization**: `source/Styles/xb3/code/actionHandler/ajaxSet_userbar.php` shows a typical handler approach: read multiple TR-181 parameters via `getStr()`, compute status values, store derived values in the session, and return JSON encoded output using `json_encode` and HTML escaping.

### Key Configuration Files

| Configuration File | Purpose | Override Mechanisms |
|--------------------|---------|--------------------|
| `source/Styles/xb3/config/lighttpd.conf` | `lighttpd` configuration including document root, modules, 404 handler, and FastCGI mapping for PHP. | Started by `webgui.sh` as `lighttpd -f /etc/lighttpd.conf`; integration is responsible for placing an appropriate `lighttpd.conf` at `/etc/lighttpd.conf`. |
| `source/Styles/xb3/config/php.ini` | PHP runtime configuration used by `php-cgi`, including loading `cosa.so` from `/fss/gw/usr/ccsp`. | Referenced by `lighttpd.conf` FastCGI `bin-path` as `php-cgi -c /fss/gw/etc/php.ini`. |
| `source/Styles/xb3/config/webgui.sh` | Startup/orchestration script that prepares logs/state and launches `lighttpd`, including captive portal related logic and environment setup. | Invoked by device integration/service manager; behavior changes based on device properties and flags read via CLI tools. |
| `source/Styles/xb3/code/CSRF-Protector-PHP/libs/config.php` | CSRF protector configuration options (token and logging related settings). | Used by the CSRF protector library; loaded when initialized by PHP includes. |
