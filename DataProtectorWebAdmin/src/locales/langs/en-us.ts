const local: App.I18n.Schema = {
  system: {
    title: 'DataProtector Web Admin',
    updateTitle: 'System Version Update Notification',
    updateContent: 'A new version of the system has been detected. Do you want to refresh the page immediately?',
    updateConfirm: 'Refresh immediately',
    updateCancel: 'Later'
  },
  common: {
    action: 'Action',
    add: 'Add',
    addSuccess: 'Add Success',
    backToHome: 'Back to home',
    batchDelete: 'Batch Delete',
    cancel: 'Cancel',
    close: 'Close',
    check: 'Check',
    selectAll: 'Select All',
    expandColumn: 'Expand Column',
    columnSetting: 'Column Setting',
    config: 'Config',
    confirm: 'Confirm',
    delete: 'Delete',
    deleteSuccess: 'Delete Success',
    confirmDelete: 'Are you sure you want to delete?',
    edit: 'Edit',
    warning: 'Warning',
    error: 'Error',
    index: 'Index',
    keywordSearch: 'Please enter keyword',
    logout: 'Logout',
    logoutConfirm: 'Are you sure you want to log out?',
    lookForward: 'Coming soon',
    modify: 'Modify',
    modifySuccess: 'Modify Success',
    noData: 'No Data',
    operate: 'Operate',
    pleaseCheckValue: 'Please check whether the value is valid',
    refresh: 'Refresh',
    reset: 'Reset',
    search: 'Search',
    switch: 'Switch',
    tip: 'Tip',
    trigger: 'Trigger',
    update: 'Update',
    updateSuccess: 'Update Success',
    userCenter: 'User Center',
    yesOrNo: {
      yes: 'Yes',
      no: 'No'
    }
  },
  request: {
    logout: 'Logout user after request failed',
    logoutMsg: 'User status is invalid, please log in again',
    logoutWithModal: 'Pop up modal after request failed and then log out user',
    logoutWithModalMsg: 'User status is invalid, please log in again',
    refreshToken: 'The requested token has expired, refresh the token',
    tokenExpired: 'The requested token has expired'
  },
  theme: {
    themeDrawerTitle: 'Theme Configuration',
    tabs: {
      appearance: 'Appearance',
      layout: 'Layout',
      general: 'General',
      preset: 'Preset'
    },
    appearance: {
      themeSchema: {
        title: 'Theme Schema',
        light: 'Light',
        dark: 'Dark',
        auto: 'Follow System'
      },
      grayscale: 'Grayscale',
      colourWeakness: 'Colour Weakness',
      themeColor: {
        title: 'Theme Color',
        primary: 'Primary',
        info: 'Info',
        success: 'Success',
        warning: 'Warning',
        error: 'Error',
        followPrimary: 'Follow Primary'
      },
      themeRadius: {
        title: 'Theme Radius'
      },
      recommendColor: 'Apply Recommended Color Algorithm',
      recommendColorDesc: 'The recommended color algorithm refers to',
      preset: {
        title: 'Theme Presets',
        apply: 'Apply',
        applySuccess: 'Preset applied successfully',
        default: {
          name: 'Default Preset',
          desc: 'Default theme preset with balanced settings'
        },
        dark: {
          name: 'Dark Preset',
          desc: 'Dark theme preset for night time usage'
        },
        compact: {
          name: 'Compact Preset',
          desc: 'Compact layout preset for small screens'
        },
        azir: {
          name: "Azir's Preset",
          desc: 'It is a cold and elegant preset that Azir likes'
        }
      }
    },
    layout: {
      layoutMode: {
        title: 'Layout Mode',
        vertical: 'Vertical Mode',
        horizontal: 'Horizontal Mode',
        'vertical-mix': 'Vertical Mix Mode',
        'vertical-hybrid-header-first': 'Left Hybrid Header-First',
        'top-hybrid-sidebar-first': 'Top-Hybrid Sidebar-First',
        'top-hybrid-header-first': 'Top-Hybrid Header-First',
        vertical_detail: 'Vertical menu layout, with the menu on the left and content on the right.',
        'vertical-mix_detail':
          'Vertical mix-menu layout, with the primary menu on the dark left side and the secondary menu on the lighter left side.',
        'vertical-hybrid-header-first_detail':
          'Left hybrid layout, with the primary menu at the top, the secondary menu on the dark left side, and the tertiary menu on the lighter left side.',
        horizontal_detail: 'Horizontal menu layout, with the menu at the top and content below.',
        'top-hybrid-sidebar-first_detail':
          'Top hybrid layout, with the primary menu on the left and the secondary menu at the top.',
        'top-hybrid-header-first_detail':
          'Top hybrid layout, with the primary menu at the top and the secondary menu on the left.'
      },
      tab: {
        title: 'Tab Settings',
        visible: 'Tab Visible',
        cache: 'Tag Bar Info Cache',
        cacheTip: 'Keep the tab bar information after leaving the page',
        height: 'Tab Height',
        mode: {
          title: 'Tab Mode',
          slider: 'Slider',
          chrome: 'Chrome',
          button: 'Button'
        },
        closeByMiddleClick: 'Close Tab by Middle Click',
        closeByMiddleClickTip: 'Enable closing tabs by clicking with the middle mouse button'
      },
      header: {
        title: 'Header Settings',
        height: 'Header Height',
        breadcrumb: {
          visible: 'Breadcrumb Visible',
          showIcon: 'Breadcrumb Icon Visible'
        }
      },
      sider: {
        title: 'Sider Settings',
        inverted: 'Dark Sider',
        width: 'Sider Width',
        collapsedWidth: 'Sider Collapsed Width',
        mixWidth: 'Mix Sider Width',
        mixCollapsedWidth: 'Mix Sider Collapse Width',
        mixChildMenuWidth: 'Mix Child Menu Width',
        autoSelectFirstMenu: 'Auto Select First Submenu',
        autoSelectFirstMenuTip:
          'When a first-level menu is clicked, the first submenu is automatically selected and navigated to the deepest level'
      },
      footer: {
        title: 'Footer Settings',
        visible: 'Footer Visible',
        fixed: 'Fixed Footer',
        height: 'Footer Height',
        right: 'Right Footer'
      },
      content: {
        title: 'Content Area Settings',
        scrollMode: {
          title: 'Scroll Mode',
          tip: 'The theme scroll only scrolls the main part, the outer scroll can carry the header and footer together',
          wrapper: 'Wrapper',
          content: 'Content'
        },
        page: {
          animate: 'Page Animate',
          mode: {
            title: 'Page Animate Mode',
            fade: 'Fade',
            'fade-slide': 'Slide',
            'fade-bottom': 'Fade Zoom',
            'fade-scale': 'Fade Scale',
            'zoom-fade': 'Zoom Fade',
            'zoom-out': 'Zoom Out',
            none: 'None'
          }
        },
        fixedHeaderAndTab: 'Fixed Header And Tab'
      }
    },
    general: {
      title: 'General Settings',
      watermark: {
        title: 'Watermark Settings',
        visible: 'Watermark Full Screen Visible',
        text: 'Custom Watermark Text',
        enableUserName: 'Enable User Name Watermark',
        enableTime: 'Show Current Time',
        timeFormat: 'Time Format'
      },
      multilingual: {
        title: 'Multilingual Settings',
        visible: 'Display multilingual button'
      },
      globalSearch: {
        title: 'Global Search Settings',
        visible: 'Display GlobalSearch button'
      }
    },
    configOperation: {
      copyConfig: 'Copy Config',
      copySuccessMsg: 'Copy Success, Please replace the variable "themeSettings" in "src/theme/settings.ts"',
      resetConfig: 'Reset Config',
      resetSuccessMsg: 'Reset Success'
    }
  },
  route: {
    login: 'Login',
    403: 'No Permission',
    404: 'Page Not Found',
    500: 'Server Error',
    'iframe-page': 'Iframe',
    home: 'Operations',
    devices: 'Devices',
    policy: 'Policy',
    'network-awareness': 'Network Awareness',
    remote: 'Remote',
    audit: 'Audit'
  },
  page: {
    login: {
      common: {
        loginOrRegister: 'Login / Register',
        userNamePlaceholder: 'Please enter user name',
        phonePlaceholder: 'Please enter phone number',
        codePlaceholder: 'Please enter verification code',
        passwordPlaceholder: 'Please enter password',
        confirmPasswordPlaceholder: 'Please enter password again',
        codeLogin: 'Verification code login',
        confirm: 'Confirm',
        back: 'Back',
        validateSuccess: 'Verification passed',
        loginSuccess: 'Login successfully',
        welcomeBack: 'Welcome back, {userName} !'
      },
      pwdLogin: {
        title: 'Password Login',
        rememberMe: 'Remember me',
        forgetPassword: 'Forget password?',
        register: 'Register',
        otherAccountLogin: 'Other Account Login',
        otherLoginMode: 'Other Login Mode',
        superAdmin: 'Super Admin',
        admin: 'Admin',
        user: 'User'
      },
      codeLogin: {
        title: 'Verification Code Login',
        getCode: 'Get verification code',
        reGetCode: 'Reacquire after {time}s',
        sendCodeSuccess: 'Verification code sent successfully',
        imageCodePlaceholder: 'Please enter image verification code'
      },
      register: {
        title: 'Register',
        agreement: 'I have read and agree to',
        protocol: '《User Agreement》',
        policy: '《Privacy Policy》'
      },
      resetPwd: {
        title: 'Reset Password'
      },
      bindWeChat: {
        title: 'Bind WeChat'
      }
    },
    home: {
      branchDesc:
        'For the convenience of everyone in developing and updating the merge, we have streamlined the code of the main branch, only retaining the homepage menu, and the rest of the content has been moved to the example branch for maintenance. The preview address displays the content of the example branch.',
      greeting: 'Good morning, {userName}, today is another day full of vitality!',
      weatherDesc: 'Today is cloudy to clear, 20℃ - 25℃!',
      projectCount: 'Project Count',
      todo: 'Todo',
      message: 'Message',
      downloadCount: 'Download Count',
      registerCount: 'Register Count',
      schedule: 'Work and rest Schedule',
      study: 'Study',
      work: 'Work',
      rest: 'Rest',
      entertainment: 'Entertainment',
      visitCount: 'Visit Count',
      turnover: 'Turnover',
      dealCount: 'Deal Count',
      projectNews: {
        title: 'Project News',
        moreNews: 'More News',
        desc1: 'Soybean created the open source project soybean-admin on May 28, 2021!',
        desc2: 'Yanbowe submitted a bug to soybean-admin, the multi-tab bar will not adapt.',
        desc3: 'Soybean is ready to do sufficient preparation for the release of soybean-admin!',
        desc4: 'Soybean is busy writing project documentation for soybean-admin!',
        desc5: 'Soybean just wrote some of the workbench pages casually, and it was enough to see!'
      },
      creativity: 'Creativity'
    }
  },
  form: {
    required: 'Cannot be empty',
    userName: {
      required: 'Please enter user name',
      invalid: 'User name format is incorrect'
    },
    phone: {
      required: 'Please enter phone number',
      invalid: 'Phone number format is incorrect'
    },
    pwd: {
      required: 'Please enter password',
      invalid: '6-18 characters, including letters, numbers, and underscores'
    },
    confirmPwd: {
      required: 'Please enter password again',
      invalid: 'The two passwords are inconsistent'
    },
    code: {
      required: 'Please enter verification code',
      invalid: 'Verification code format is incorrect'
    },
    email: {
      required: 'Please enter email',
      invalid: 'Email format is incorrect'
    }
  },
  dropdown: {
    closeCurrent: 'Close Current',
    closeOther: 'Close Other',
    closeLeft: 'Close Left',
    closeRight: 'Close Right',
    closeAll: 'Close All',
    pin: 'Pin Tab',
    unpin: 'Unpin Tab'
  },
  icon: {
    themeConfig: 'Theme Configuration',
    themeSchema: 'Theme Schema',
    lang: 'Switch Language',
    fullscreen: 'Fullscreen',
    fullscreenExit: 'Exit Fullscreen',
    reload: 'Reload Page',
    collapse: 'Collapse Menu',
    expand: 'Expand Menu',
    pin: 'Pin',
    unpin: 'Unpin'
  },
  datatable: {
    itemCount: 'Total {total} items',
    fixed: {
      left: 'Left Fixed',
      right: 'Right Fixed',
      unFixed: 'Unfixed'
    }
  },
  dataprotector: {
    common: {
      action: 'Action',
      actions: 'Actions',
      active: 'Active',
      inactive: 'Inactive',
      add: 'Add',
      apply: 'Apply',
      authorize: 'Authorize',
      block: 'Block',
      blocked: 'Blocked',
      cancel: 'Cancel',
      capture: 'Capture',
      clear: 'Clear',
      completed: 'Completed',
      connected: 'Connected',
      delete: 'Delete',
      disabled: 'Disabled',
      enabled: 'Enabled',
      enforcing: 'Enforcing',
      failed: 'Failed',
      inactiveState: 'Inactive',
      lock: 'Lock',
      offline: 'Offline',
      online: 'Online',
      open: 'Open',
      read: 'Read',
      readOnly: 'Read-only',
      refresh: 'Refresh',
      refreshPanel: 'Refresh Panel',
      remove: 'Remove',
      rename: 'Rename',
      reset: 'Reset',
      allowed: 'Allowed',
      save: 'Save',
      search: 'Search',
      send: 'Send',
      start: 'Start',
      stop: 'Stop',
      stopped: 'Stopped',
      unknown: 'unknown',
      writable: 'Writable'
    },
    home: {
      title: 'DataProtector Operations',
      subtitle: 'Central control plane for endpoint policy distribution, agent health, and audit visibility.',
      centralServer: 'Central server',
      onlineAgents: 'Online agents',
      registered: 'Registered: {count}',
      trustedRules: 'Trusted rules',
      excludedDirectories: 'Excluded directories: {count}',
      policyVersion: 'Policy version',
      noRulesYet: 'No rules yet',
      serverDetails: 'Central Server Details',
      message: 'Message',
      machine: 'Machine',
      user: 'User',
      processId: 'Process ID',
      statePath: 'State path',
      bridgeNotQueried: 'Bridge not queried yet.',
      agentHealth: 'Agent Health',
      noAgentsRegistered: 'No agents registered',
      recentAudit: 'Recent Audit',
      noAuditEvents: 'No audit events'
    },
    devices: {
      title: 'Agent Devices',
      subtitle: 'Clients actively synchronize with the central server and apply policy to their local driver.',
      registeredAgents: 'Registered agents',
      onlineAgents: 'Online agents',
      driverConnected: 'Driver connected',
      inventory: 'Agent Inventory',
      columns: {
        agent: 'Agent',
        online: 'Online',
        driver: 'Driver',
        user: 'User',
        policy: 'Policy',
        lastSeen: 'Last Seen',
        applyResult: 'Apply Result',
        deviceId: 'Device ID'
      }
    },
    networkAwareness: {
      title: 'Network Awareness',
      newConnections: 'New connections',
      newSinceBaseline: 'New since baseline',
      http3Candidates: 'HTTP/3 candidates',
      unsignedProcesses: 'Unsigned processes',
      connectionTrend: 'Connection Trend',
      eventDistribution: 'Event Distribution',
      ipIntelligence: 'IP Intelligence',
      configuredBy: 'Configured by {source}',
      notConfigured: 'Not configured',
      tokenPlaceholder: 'ipinfo token',
      saveToken: 'Save',
      clearToken: 'Clear',
      tokenRequired: 'Token is required',
      tokenSaved: 'IP intelligence token saved',
      tokenCleared: 'IP intelligence token cleared',
      searchPlaceholder: 'Remote, process, signer, hash',
      showLanRemotes: 'Show LAN remotes',
      allHosts: 'All hosts',
      noEvents: 'No events',
      setTokenHint: 'Set DATAPROTECTOR_IPINFO_TOKEN on the server',
      privateRemote: 'Private or non-IP remote',
      pending: 'Pending',
      lookupFailed: 'Lookup failed',
      notApplicable: 'Private or non-IP remote',
      eventTypes: {
        all: 'All',
        connection: 'Connection',
        dns: 'DNS',
        quic: 'QUIC',
        http3: 'HTTP/3',
        blocked: 'Blocked'
      },
      baselines: {
        hours5: '5 hours',
        day1: '1 day',
        days3: '3 days',
        days7: '7 days',
        month1: '1 month'
      },
      charts: {
        observed: 'Observed',
        new: 'New',
        quic: 'QUIC',
        eventType: 'Event type'
      },
      columns: {
        remote: 'Remote',
        process: 'Process',
        type: 'Type',
        ipInfo: 'IP Intelligence',
        signature: 'Signature',
        file: 'File',
        hash: 'Hash',
        host: 'Host',
        seen: 'Seen',
        count: 'count {count}',
        unknown: 'unknown'
      }
    },
    audit: {
      title: 'Audit Center',
      allEvents: 'All events',
      policy: 'Policy',
      networkDefense: 'Network defense',
      smtpAudit: 'SMTP audit',
      webshell: 'WebShell',
      hashdump: 'Hash dump',
      lateral: 'Lateral movement',
      remoteOps: 'Remote ops',
      agentSync: 'Agent sync',
      system: 'System',
      allSeverity: 'All severity',
      critical: 'Critical',
      warning: 'Warning',
      info: 'Info',
      operational: 'Operational',
      allDisposition: 'All disposition',
      observed: 'Observed',
      loadedEvents: 'Loaded events',
      criticalEvents: 'Critical events',
      warningEvents: 'Warning events',
      blockedActions: 'Blocked actions',
      eventType: 'Event type',
      host: 'Host',
      severity: 'Severity',
      disposition: 'Disposition',
      timeRange: 'Time range',
      searchPlaceholder: 'Search action, host, target, status, or message',
      securityTrend: 'Security Trend',
      eventTypeDistribution: 'Event Type Distribution',
      hostAnalytics: 'Host Analytics',
      eventClassification: 'Event Classification',
      auditEvents: 'Audit Events',
      noEvents: 'No events',
      allOnlineAgents: 'All online agents',
      total: 'Total',
      criticalCount: '{count} critical',
      limits: {
        last200: 'Last 200',
        last500: 'Last 500',
        last1000: 'Last 1000'
      },
      columns: {
        time: 'Time',
        type: 'Type',
        events: 'Events',
        action: 'Action',
        target: 'Target',
        status: 'Status',
        message: 'Message'
      }
    },
    remote: {
      endpoints: 'Endpoints',
      clients: 'Clients',
      online: '{count} online',
      registered: '{count} registered',
      noRegisteredEndpoints: 'No registered endpoints',
      driverUnknown: 'driver unknown',
      remoteManagement: 'Remote Management',
      selectEndpoint: 'Select an endpoint',
      tabs: {
        files: 'File Manager',
        processes: 'Process Manager',
        apps: 'Applications',
        startup: 'Startup',
        shell: 'Command',
        desktop: 'Desktop',
        accounts: 'Accounts'
      },
      files: {
        pathPlaceholder: 'Select a drive or enter a remote path',
        hint: 'Double-click folders or drives to enter. Right-click items for actions.',
        noDrives: 'No drives returned',
        notReady: 'not ready',
        freeOf: '{free} free of {total}',
        currentPath: 'Current path',
        newName: 'New name',
        renameTitle: 'Rename Remote Item',
        deleteTitle: 'Delete remote item',
        deleteContent: 'Delete {path}?'
      },
      processes: {
        searchPlaceholder: 'Search process name, PID, path, or user',
        hint: 'Right-click a process to terminate it.',
        terminate: 'Terminate',
        terminateTitle: 'Terminate process',
        terminateContent: 'Terminate {name} ({pid}) on {target}?'
      },
      apps: {
        installed: '{count} installed applications',
        unnamed: 'Unnamed application',
        unknownPublisher: 'Unknown publisher'
      },
      startup: {
        entries: '{count} startup entries'
      },
      shell: {
        connected: 'Connected',
        stopped: 'Stopped',
        empty: 'Start a session, then type commands below. Press Enter to send.',
        inputPlaceholder: 'Type a command and press Enter'
      },
      desktop: {
        title: 'Remote desktop snapshot',
        screenshotAlt: 'Remote desktop screenshot',
        noScreenshot: 'No screenshot captured',
        invalidScreenshot: 'The endpoint returned an invalid or truncated screenshot payload.'
      },
      accounts: {
        username: 'Username',
        newPassword: 'New password',
        changePassword: 'Change Password',
        passwordChanged: 'Password change task completed.'
      },
      activity: {
        title: 'Activity',
        empty: 'No remote operations in this session',
        queued: 'Queued {operation}',
        completed: 'Completed {operation}',
        renamed: 'Renamed {name}',
        deleted: 'Deleted {name}',
        terminated: 'Terminated {name} ({pid})',
        passwordChanged: 'Password changed for {username}',
        lockRequested: 'Remote workstation lock requested'
      },
      columns: {
        name: 'Name',
        type: 'Type',
        size: 'Size',
        modified: 'Modified',
        folder: 'Folder',
        file: 'File',
        process: 'Process',
        memory: 'Memory',
        started: 'Started',
        path: 'Path',
        location: 'Location',
        command: 'Command',
        state: 'State'
      },
      status: {
        online: 'online',
        offline: 'offline'
      },
      operations: {
        file: {
          drives: 'drive inventory',
          list: 'directory listing',
          delete: 'file deletion',
          rename: 'file rename'
        },
        process: {
          list: 'process inventory',
          kill: 'process termination'
        },
        inventory: {
          installedApps: 'application inventory',
          startupItems: 'startup inventory'
        },
        cmd: {
          run: 'remote command'
        },
        terminal: {
          start: 'terminal start',
          input: 'terminal input',
          read: 'terminal output read',
          stop: 'terminal stop'
        },
        desktop: {
          screenshot: 'desktop screenshot'
        },
        session: {
          lock: 'screen lock'
        },
        user: {
          changePassword: 'password change'
        }
      },
      errors: {
        selectEndpoint: 'Select an endpoint first.',
        queueFailed: 'Unable to queue remote operation.',
        operationFailed: '{operation} failed.',
        timeout: '{operation} timed out waiting for the endpoint.'
      }
    },
    policy: {
      title: 'Policy Management',
      subtitle: 'Extension-bound central policy distributed to all registered DataProtector agents.',
      centralOnline: 'Central server online',
      serverOffline: 'Server offline',
      tabs: {
        file: 'File Policy',
        network: 'Network Defense',
        lateral: 'IPC / SMB Defense',
        webshell: 'WebShell Defense',
        hashprotect: 'Anti-Dump / Hash Protection',
        device: 'Device Control'
      },
      file: {
        addTitle: 'Add File Rule',
        inventory: 'Central File Rule Inventory',
        ruleKind: 'Rule kind',
        extension: 'Extension',
        ruleValue: 'Rule value',
        addButton: 'Add to Central Policy',
        process: 'Process',
        directory: 'Directory',
        excluded: 'Excluded',
        processName: 'Process name',
        processDirectory: 'Process directory',
        excludedDirectory: 'Excluded directory',
        kind: 'Kind',
        value: 'Value',
        added: 'Rule added to central policy.',
        removed: 'Rule removed from central policy.',
        clearTitle: 'Clear file rules',
        clearContent: 'This removes every trusted process, trusted directory, and excluded directory rule from the central policy.',
        clearSuccess: 'Central file policy cleared.'
      },
      network: {
        quickActions: 'Quick Network Actions',
        inboundIcmp: 'Inbound ICMP',
        hardening: 'Endpoint hardening',
        disablePing: 'Disable Inbound Ping',
        addTitle: 'Add Network Rule',
        inventory: 'Central Network Rule Inventory',
        kind: 'Rule kind',
        action: 'Action',
        domain: 'Domain',
        remoteIp: 'Remote IPv4 / CIDR',
        protocol: 'Protocol',
        direction: 'Direction',
        localPort: 'Local port',
        remotePort: 'Remote port',
        addButton: 'Add Network Rule',
        domains: 'Domains',
        ip: 'IP',
        icmp: 'ICMP',
        ruleId: 'Rule ID',
        target: 'Target',
        port: 'Port',
        allow: 'Allow',
        any: 'Any',
        outbound: 'Outbound',
        inbound: 'Inbound',
        both: 'Both',
        allPingTargets: '* for all ping targets',
        cidrPlaceholder: '203.0.113.10 or 203.0.113.0/24',
        added: 'Network rule added to central policy.',
        removed: 'Network rule removed from central policy.',
        pingAdded: 'Inbound ping block rule added.',
        clearTitle: 'Clear network rules',
        clearContent: 'This removes every network allow/block rule from the central policy.',
        clearSuccess: 'Central network policy cleared.'
      },
      lateral: {
        title: 'Lateral Movement Defense Policy',
        enforcement: 'Protection enforcement',
        enforcementDesc: 'Central policy controls SMB executable staging and IPC remote execution surfaces.',
        smbCopy: 'SMB executable copy',
        smbCopyDesc: 'Blocks executable payload creation, write and rename on remote-origin SMB file operations.',
        ipcTasks: 'IPC scheduled tasks',
        ipcTasksDesc: 'Blocks remote Task Scheduler named-pipe access and matching command-line launch patterns.',
        ipcServices: 'IPC service creation',
        ipcServicesDesc: 'Blocks Service Control Manager named-pipe abuse and remote service command patterns.',
        remoteTools: 'Remote admin tools',
        remoteToolsDesc: 'Blocks schtasks, at, sc, wmic and PowerShell remoting process creation before execution.',
        controls: 'Controls: {count}/4',
        flags: 'Flags: {flags}',
        active: 'Active: {count}',
        save: 'Save Lateral Defense',
        surfaces: 'Protected Lateral Movement Surfaces',
        smbStaging: 'SMB executable staging',
        smbStagingDesc: 'Blocks remote-origin writes, creates and renames that land executable payloads through SMB shares.',
        ipcTaskScheduler: 'IPC task scheduler',
        ipcTaskSchedulerDesc: 'Blocks named-pipe access used by AT and Task Scheduler RPC lateral movement.',
        ipcServiceControl: 'IPC service control',
        ipcServiceControlDesc: 'Blocks Service Control Manager named-pipe abuse for remote service creation and execution.',
        remoteAdminLaunch: 'Remote admin tool launch',
        remoteAdminLaunchDesc: 'Blocks schtasks, at, sc, wmic and PowerShell remoting launch patterns before execution.',
        saved: 'Lateral movement defense policy saved to central policy.'
      },
      webshell: {
        addTitle: 'Add Protected Web Directory',
        inventory: 'Protected Web Directory Inventory',
        webRoot: 'Web root directory',
        addButton: 'Add WebShell Defense Rule',
        directories: 'Directories',
        dangerEnabled: 'Danger blocks enabled',
        protectedDirectory: 'Protected web directory',
        detection: 'Detection',
        webScripts: 'Web scripts',
        added: 'WebShell defense rule added to central policy.',
        removed: 'WebShell defense rule removed from central policy.',
        clearTitle: 'Clear WebShell rules',
        clearContent: 'This removes every protected web directory from the central policy.',
        clearSuccess: 'Central WebShell policy cleared.'
      },
      hashprotect: {
        title: 'Hash Dump Protection Policy',
        enforcement: 'Protection enforcement',
        enforcementDesc: 'Central policy version controls how agents harden credential dump surfaces.',
        lsass: 'LSASS handles',
        lsassDesc: 'Blocks untrusted process memory dump handle access.',
        credentialFiles: 'Credential files',
        credentialFilesDesc: 'Blocks SAM, SYSTEM, SECURITY, NTDS and shadow-copy paths.',
        registryHives: 'Registry hives',
        registryHivesDesc: 'Blocks save, restore and replace against credential hives.',
        rawExtents: 'Raw extents',
        rawExtentsDesc: 'Denies only raw reads that overlap credential file disk ranges.',
        features: 'Features: {count}/4',
        assets: 'Assets: {count}',
        save: 'Save Anti-Dump Policy',
        surfaces: 'Protected Surfaces',
        saved: 'Anti-dump policy saved to central policy.',
        assetsList: {
          lsassTitle: 'LSASS process memory',
          lsassDetail: 'Strips VM_READ, DUP_HANDLE and related dangerous process-handle access from untrusted callers.',
          filesTitle: 'Offline credential stores',
          filesDetail: 'Blocks direct access to SAM, SECURITY, SYSTEM, NTDS.dit, RegBack, Repair and Volume Shadow Copy aliases.',
          registryTitle: 'Registry hive export paths',
          registryDetail: 'Blocks hive save, restore and replace operations against HKLM SAM, SECURITY and SYSTEM.',
          rawTitle: 'Raw disk sensitive extents',
          rawDetail: 'Allows raw volume reads except when the byte range overlaps sensitive hive and NTDS file extents.'
        }
      },
      device: {
        discovered: 'Discovered Removable Devices',
        addTitle: 'Add Removable Storage Rule',
        inventory: 'Central Device Rule Inventory',
        pending: 'Pending',
        authorized: 'Authorized',
        blocked: 'Blocked',
        deviceId: 'Device identifier',
        insertionAccess: 'Insertion access',
        allowInsert: 'Allow insert',
        allowed: 'Allowed',
        allowWrite: 'Allow write',
        writeAccess: 'Write access',
        rules: 'Rules',
        addButton: 'Add Device Rule',
        allStorage: 'All removable storage',
        access: 'Access',
        write: 'Write',
        device: 'Device',
        host: 'Host',
        volumes: 'Volumes',
        hardwareCode: 'Hardware code',
        status: 'Status',
        seen: 'Seen',
        reset: 'Reset',
        added: 'Device control rule added to central policy.',
        removed: 'Device control rule removed from central policy.',
        clearTitle: 'Clear device control rules',
        clearContent: 'This removes all removable storage access and write policies from the central policy.',
        clearSuccess: 'Central device control policy cleared.',
        authorizedWritable: 'Removable device authorized.',
        authorizedReadonly: 'Removable device authorized as read-only.',
        blockedDevice: 'Removable device blocked.',
        authorizationRemoved: 'Removable device authorization reset.',
        removableStorage: 'Removable storage',
        volumeCount: '{count} volume(s)'
      },
      validation: {
        ruleKind: 'Rule kind is required',
        ruleValue: 'Rule value is required',
        extension: 'Extension is required',
        action: 'Action is required',
        protocol: 'Protocol is required',
        direction: 'Direction is required',
        domain: 'Domain is required',
        remoteAddress: 'Remote address is required',
        protectedDirectory: 'Protected web directory is required',
        deviceId: 'Device identifier is required'
      }
    }
  }
};

export default local;
