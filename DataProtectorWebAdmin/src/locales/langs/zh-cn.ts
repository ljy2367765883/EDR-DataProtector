const local: App.I18n.Schema = {
  system: {
    title: 'DataProtector Web Admin',
    updateTitle: '系统版本更新通知',
    updateContent: '检测到系统有新版本发布，是否立即刷新页面？',
    updateConfirm: '立即刷新',
    updateCancel: '稍后再说'
  },
  common: {
    action: '操作',
    add: '新增',
    addSuccess: '添加成功',
    backToHome: '返回首页',
    batchDelete: '批量删除',
    cancel: '取消',
    close: '关闭',
    check: '勾选',
    selectAll: '全选',
    expandColumn: '展开列',
    columnSetting: '列设置',
    config: '配置',
    confirm: '确认',
    delete: '删除',
    deleteSuccess: '删除成功',
    confirmDelete: '确认删除吗？',
    edit: '编辑',
    warning: '警告',
    error: '错误',
    index: '序号',
    keywordSearch: '请输入关键词搜索',
    logout: '退出登录',
    logoutConfirm: '确认退出登录吗？',
    lookForward: '敬请期待',
    modify: '修改',
    modifySuccess: '修改成功',
    noData: '无数据',
    operate: '操作',
    pleaseCheckValue: '请检查输入的值是否合法',
    refresh: '刷新',
    reset: '重置',
    search: '搜索',
    switch: '切换',
    tip: '提示',
    trigger: '触发',
    update: '更新',
    updateSuccess: '更新成功',
    userCenter: '个人中心',
    yesOrNo: {
      yes: '是',
      no: '否'
    }
  },
  request: {
    logout: '请求失败后登出用户',
    logoutMsg: '用户状态失效，请重新登录',
    logoutWithModal: '请求失败后弹出模态框再登出用户',
    logoutWithModalMsg: '用户状态失效，请重新登录',
    refreshToken: '请求的token已过期，刷新token',
    tokenExpired: 'token已过期'
  },
  theme: {
    themeDrawerTitle: '主题配置',
    tabs: {
      appearance: '外观',
      layout: '布局',
      general: '通用',
      preset: '预设'
    },
    appearance: {
      themeSchema: {
        title: '主题模式',
        light: '亮色模式',
        dark: '暗黑模式',
        auto: '跟随系统'
      },
      grayscale: '灰色模式',
      colourWeakness: '色弱模式',
      themeColor: {
        title: '主题颜色',
        primary: '主色',
        info: '信息色',
        success: '成功色',
        warning: '警告色',
        error: '错误色',
        followPrimary: '跟随主色'
      },
      themeRadius: {
        title: '主题圆角'
      },
      recommendColor: '应用推荐算法的颜色',
      recommendColorDesc: '推荐颜色的算法参照',
      preset: {
        title: '主题预设',
        apply: '应用',
        applySuccess: '预设应用成功',
        default: {
          name: '默认预设',
          desc: 'Soybean 默认主题预设'
        },
        dark: {
          name: '暗色预设',
          desc: '适用于夜间使用的暗色主题预设'
        },
        compact: {
          name: '紧凑型',
          desc: '适用于小屏幕的紧凑布局预设'
        },
        azir: {
          name: 'Azir的预设',
          desc: '是 Azir 比较喜欢的莫兰迪色系冷淡风'
        }
      }
    },
    layout: {
      layoutMode: {
        title: '布局模式',
        vertical: '左侧菜单模式',
        'vertical-mix': '左侧菜单混合模式',
        'vertical-hybrid-header-first': '左侧混合-顶部优先',
        horizontal: '顶部菜单模式',
        'top-hybrid-sidebar-first': '顶部混合-侧边优先',
        'top-hybrid-header-first': '顶部混合-顶部优先',
        vertical_detail: '左侧菜单布局，菜单在左，内容在右。',
        'vertical-mix_detail': '左侧双菜单布局，一级菜单在左侧深色区域，二级菜单在左侧浅色区域。',
        'vertical-hybrid-header-first_detail':
          '左侧混合布局，一级菜单在顶部，二级菜单在左侧深色区域，三级菜单在左侧浅色区域。',
        horizontal_detail: '顶部菜单布局，菜单在顶部，内容在下方。',
        'top-hybrid-sidebar-first_detail': '顶部混合布局，一级菜单在左侧，二级菜单在顶部。',
        'top-hybrid-header-first_detail': '顶部混合布局，一级菜单在顶部，二级菜单在左侧。'
      },
      tab: {
        title: '标签栏设置',
        visible: '显示标签栏',
        cache: '标签栏信息缓存',
        cacheTip: '离开页面后仍然保留标签栏信息',
        height: '标签栏高度',
        mode: {
          title: '标签栏风格',
          slider: '滑块风格',
          chrome: '谷歌风格',
          button: '按钮风格'
        },
        closeByMiddleClick: '鼠标中键关闭标签页',
        closeByMiddleClickTip: '启用后可以使用鼠标中键点击标签页进行关闭'
      },
      header: {
        title: '头部设置',
        height: '头部高度',
        breadcrumb: {
          visible: '显示面包屑',
          showIcon: '显示面包屑图标'
        }
      },
      sider: {
        title: '侧边栏设置',
        inverted: '深色侧边栏',
        width: '侧边栏宽度',
        collapsedWidth: '侧边栏折叠宽度',
        mixWidth: '混合布局侧边栏宽度',
        mixCollapsedWidth: '混合布局侧边栏折叠宽度',
        mixChildMenuWidth: '混合布局子菜单宽度',
        autoSelectFirstMenu: '自动选择第一个子菜单',
        autoSelectFirstMenuTip: '点击一级菜单时，自动选择并导航到第一个子菜单的最深层级'
      },
      footer: {
        title: '底部设置',
        visible: '显示底部',
        fixed: '固定底部',
        height: '底部高度',
        right: '底部居右'
      },
      content: {
        title: '内容区域设置',
        scrollMode: {
          title: '滚动模式',
          tip: '主题滚动仅 main 部分滚动，外层滚动可携带头部底部一起滚动',
          wrapper: '外层滚动',
          content: '主体滚动'
        },
        page: {
          animate: '页面切换动画',
          mode: {
            title: '页面切换动画类型',
            'fade-slide': '滑动',
            fade: '淡入淡出',
            'fade-bottom': '底部消退',
            'fade-scale': '缩放消退',
            'zoom-fade': '渐变',
            'zoom-out': '闪现',
            none: '无'
          }
        },
        fixedHeaderAndTab: '固定头部和标签栏'
      }
    },
    general: {
      title: '通用设置',
      watermark: {
        title: '水印设置',
        visible: '显示全屏水印',
        text: '自定义水印文本',
        enableUserName: '启用用户名水印',
        enableTime: '显示当前时间',
        timeFormat: '时间格式'
      },
      multilingual: {
        title: '多语言设置',
        visible: '显示多语言按钮'
      },
      globalSearch: {
        title: '全局搜索设置',
        visible: '显示全局搜索按钮'
      }
    },
    configOperation: {
      copyConfig: '复制配置',
      copySuccessMsg: '复制成功，请替换 src/theme/settings.ts 中的变量 themeSettings',
      resetConfig: '重置配置',
      resetSuccessMsg: '重置成功'
    }
  },
  route: {
    login: '登录',
    403: '无权限',
    404: '页面不存在',
    500: '服务器错误',
    'iframe-page': '外链页面',
    home: '运行态',
    devices: '设备',
    policy: '策略',
    'network-awareness': '网络感知',
    remote: '远程',
    sandbox: '轻量沙箱',
    audit: '审计'
  },
  page: {
    login: {
      common: {
        loginOrRegister: '登录 / 注册',
        userNamePlaceholder: '请输入用户名',
        phonePlaceholder: '请输入手机号',
        codePlaceholder: '请输入验证码',
        passwordPlaceholder: '请输入密码',
        confirmPasswordPlaceholder: '请再次输入密码',
        codeLogin: '验证码登录',
        confirm: '确定',
        back: '返回',
        validateSuccess: '验证成功',
        loginSuccess: '登录成功',
        welcomeBack: '欢迎回来，{userName} ！'
      },
      pwdLogin: {
        title: '密码登录',
        rememberMe: '记住我',
        forgetPassword: '忘记密码？',
        register: '注册账号',
        otherAccountLogin: '其他账号登录',
        otherLoginMode: '其他登录方式',
        superAdmin: '超级管理员',
        admin: '管理员',
        user: '普通用户'
      },
      codeLogin: {
        title: '验证码登录',
        getCode: '获取验证码',
        reGetCode: '{time}秒后重新获取',
        sendCodeSuccess: '验证码发送成功',
        imageCodePlaceholder: '请输入图片验证码'
      },
      register: {
        title: '注册账号',
        agreement: '我已经仔细阅读并接受',
        protocol: '《用户协议》',
        policy: '《隐私权政策》'
      },
      resetPwd: {
        title: '重置密码'
      },
      bindWeChat: {
        title: '绑定微信'
      }
    },
    home: {
      branchDesc:
        '为了方便大家开发和更新合并，我们对main分支的代码进行了精简，只保留了首页菜单，其余内容已移至example分支进行维护。预览地址显示的内容即为example分支的内容。',
      greeting: '早安，{userName}, 今天又是充满活力的一天!',
      weatherDesc: '今日多云转晴，20℃ - 25℃!',
      projectCount: '项目数',
      todo: '待办',
      message: '消息',
      downloadCount: '下载量',
      registerCount: '注册量',
      schedule: '作息安排',
      study: '学习',
      work: '工作',
      rest: '休息',
      entertainment: '娱乐',
      visitCount: '访问量',
      turnover: '成交额',
      dealCount: '成交量',
      projectNews: {
        title: '项目动态',
        moreNews: '更多动态',
        desc1: 'Soybean 在2021年5月28日创建了开源项目 soybean-admin!',
        desc2: 'Yanbowe 向 soybean-admin 提交了一个bug，多标签栏不会自适应。',
        desc3: 'Soybean 准备为 soybean-admin 的发布做充分的准备工作!',
        desc4: 'Soybean 正在忙于为soybean-admin写项目说明文档！',
        desc5: 'Soybean 刚才把工作台页面随便写了一些，凑合能看了！'
      },
      creativity: '创意'
    }
  },
  form: {
    required: '不能为空',
    userName: {
      required: '请输入用户名',
      invalid: '用户名格式不正确'
    },
    phone: {
      required: '请输入手机号',
      invalid: '手机号格式不正确'
    },
    pwd: {
      required: '请输入密码',
      invalid: '密码格式不正确，6-18位字符，包含字母、数字、下划线'
    },
    confirmPwd: {
      required: '请输入确认密码',
      invalid: '两次输入密码不一致'
    },
    code: {
      required: '请输入验证码',
      invalid: '验证码格式不正确'
    },
    email: {
      required: '请输入邮箱',
      invalid: '邮箱格式不正确'
    }
  },
  dropdown: {
    closeCurrent: '关闭',
    closeOther: '关闭其它',
    closeLeft: '关闭左侧',
    closeRight: '关闭右侧',
    closeAll: '关闭所有',
    pin: '固定标签',
    unpin: '取消固定'
  },
  icon: {
    themeConfig: '主题配置',
    themeSchema: '主题模式',
    lang: '切换语言',
    fullscreen: '全屏',
    fullscreenExit: '退出全屏',
    reload: '刷新页面',
    collapse: '折叠菜单',
    expand: '展开菜单',
    pin: '固定',
    unpin: '取消固定'
  },
  datatable: {
    itemCount: '共 {total} 条',
    fixed: {
      left: '左固定',
      right: '右固定',
      unFixed: '取消固定'
    }
  },
  dataprotector: {
    common: {
      action: '操作',
      actions: '操作',
      active: '启用',
      inactive: '未启用',
      add: '添加',
      apply: '应用',
      authorize: '授权',
      block: '阻止',
      blocked: '已阻止',
      cancel: '取消',
      capture: '截图',
      clear: '清空',
      completed: '已完成',
      connected: '已连接',
      delete: '删除',
      disabled: '已禁用',
      enabled: '已启用',
      enforcing: '防护中',
      failed: '失败',
      inactiveState: '未启用',
      lock: '锁屏',
      offline: '离线',
      online: '在线',
      open: '打开',
      read: '读取',
      readOnly: '只读',
      refresh: '刷新',
      refreshPanel: '刷新面板',
      remove: '移除',
      rename: '重命名',
      reset: '重置',
      allowed: '已允许',
      save: '保存',
      search: '搜索',
      send: '发送',
      start: '启动',
      stop: '停止',
      stopped: '已停止',
      unknown: '未知',
      writable: '可写'
    },
    home: {
      title: 'DataProtector 运行中心',
      subtitle: '统一管理终端策略下发、Agent 健康状态与审计可视化。',
      centralServer: '中央服务器',
      onlineAgents: '在线 Agent',
      registered: '已注册：{count}',
      trustedRules: '授信规则',
      excludedDirectories: '排除目录：{count}',
      policyVersion: '策略版本',
      noRulesYet: '暂无规则',
      serverDetails: '中央服务器详情',
      message: '消息',
      machine: '主机',
      user: '用户',
      processId: '进程 ID',
      statePath: '状态路径',
      bridgeNotQueried: '尚未查询桥接服务。',
      agentHealth: 'Agent 健康状态',
      noAgentsRegistered: '暂无注册 Agent',
      recentAudit: '最近审计',
      noAuditEvents: '暂无审计事件'
    },
    devices: {
      title: 'Agent 设备',
      subtitle: '客户端主动同步中央服务器策略，并将策略应用到本地驱动。',
      registeredAgents: '已注册 Agent',
      onlineAgents: '在线 Agent',
      driverConnected: '驱动已连接',
      inventory: 'Agent 清单',
      deleteTitle: '删除 Agent',
      deleteContent: '确认删除 {name} 的 Agent 清单吗？该 Agent 的排队任务和网络感知缓存也会被移除。',
      deleteSuccess: 'Agent 清单已删除。',
      columns: {
        agent: 'Agent',
        online: '在线状态',
        driver: '驱动',
        user: '用户',
        policy: '策略',
        lastSeen: '最近在线',
        applyResult: '应用结果',
        deviceId: '设备 ID'
      }
    },
    networkAwareness: {
      title: '网络感知',
      newConnections: '新增连接',
      filteredConnections: '过滤后连接',
      newSinceBaseline: '相对基线新增',
      http3Candidates: 'HTTP/3 候选',
      unsignedProcesses: '未签名进程',
      connectionTrend: '连接趋势',
      eventDistribution: '事件分布',
      ipIntelligence: 'IP 情报',
      configuredBy: '由 {source} 配置',
      notConfigured: '未配置',
      tokenPlaceholder: 'ipinfo token',
      saveToken: '保存',
      clearToken: '清空',
      tokenRequired: 'Token 不能为空',
      tokenSaved: 'IP 情报 Token 已保存',
      tokenCleared: 'IP 情报 Token 已清空',
      searchPlaceholder: '远端、进程、签名者、哈希',
      showLanRemotes: '显示局域网远端',
      allHosts: '全部主机',
      noEvents: '暂无事件',
      setTokenHint: '请在服务器配置 DATAPROTECTOR_IPINFO_TOKEN',
      privateRemote: '私有地址或非 IP 远端',
      pending: '待查询',
      lookupFailed: '查询失败',
      notApplicable: '私有地址或非 IP 远端',
      eventTypes: {
        all: '全部',
        connection: '连接',
        dns: 'DNS',
        quic: 'QUIC',
        http3: 'HTTP/3',
        blocked: '已阻止'
      },
      newnessFilters: {
        all: '全部连接',
        newOnly: '仅新增',
        existingOnly: '仅已存在'
      },
      baselines: {
        hours5: '5 小时',
        day1: '1 天',
        days3: '3 天',
        days7: '7 天',
        month1: '1 个月'
      },
      charts: {
        observed: '已观察',
        new: '新增',
        quic: 'QUIC',
        eventType: '事件类型'
      },
      columns: {
        remote: '远端',
        process: '进程',
        type: '类型',
        ipInfo: 'IP 情报',
        signature: '签名',
        file: '文件',
        hash: '哈希',
        host: '主机',
        seen: '发现时间',
        count: '次数 {count}',
        unknown: '未知'
      }
    },
    audit: {
      title: '审计中心',
      allEvents: '全部事件',
      policy: '策略',
      networkDefense: '网络防御',
      smtpAudit: 'SMTP 审计',
      webshell: 'WebShell',
      hashdump: 'Hash Dump',
      lateral: '横向移动',
      dlp: '数据防泄密',
      remoteOps: '远程操作',
      agentSync: 'Agent 同步',
      system: '系统',
      allSeverity: '全部严重性',
      critical: '严重',
      warning: '警告',
      info: '信息',
      operational: '运行',
      allDisposition: '全部处置',
      observed: '已观察',
      loadedEvents: '已加载事件',
      criticalEvents: '严重事件',
      warningEvents: '警告事件',
      blockedActions: '已阻止操作',
      eventType: '事件类型',
      host: '主机',
      severity: '严重性',
      disposition: '处置',
      timeRange: '时间范围',
      searchPlaceholder: '搜索操作、主机、目标、状态或消息',
      securityTrend: '安全趋势',
      eventTypeDistribution: '事件类型分布',
      hostAnalytics: '主机分析',
      eventClassification: '事件分类',
      auditEvents: '审计事件',
      noEvents: '暂无事件',
      allOnlineAgents: '全部在线 Agent',
      total: '总量',
      userhook: '进程威胁感知',
      criticalCount: '{count} 个严重',
      clearTitle: '清空审计日志',
      clearContent: '这会移除当前中央审计历史，并保留一条清空操作记录。',
      clearSuccess: '审计日志已清空。',
      deleteTitle: '删除审计事件',
      deleteContent: '确认删除 {action} / {target} 这条审计事件吗？',
      deleteSuccess: '审计事件已删除。',
      limits: {
        last200: '最近 200 条',
        last500: '最近 500 条',
        last1000: '最近 1000 条'
      },
      columns: {
        time: '时间',
        type: '类型',
        events: '事件数',
        source: '来源',
        object: '对象',
        action: '操作',
        target: '目标',
        status: '状态',
        message: '消息'
      },
      attackFlow: {
        title: '攻击流程还原',
        empty: '当前筛选范围内暂无可关联的攻击流程。',
        activeStages: '{count} 个阶段',
        events: '{count} 条证据',
        incidents: '关联事件簇',
        processes: '进程画像',
        timeline: '证据时间线',
        entities: '关键实体',
        stages: {
          delivery: '落地 / 投递',
          execution: '执行',
          behavior: '危险行为',
          credential: '凭据访问',
          lateral: '横向移动',
          network: '外联 / C2',
          persistence: '持久化',
          impact: '影响 / 数据'
        },
        columns: {
          root: '根进程',
          stages: '阶段',
          remotes: '远端',
          events: '事件',
          score: '分数',
          process: '进程'
        }
      }
    },
    remote: {
      endpoints: '终端',
      clients: '客户端',
      online: '{count} 在线',
      registered: '{count} 已注册',
      noRegisteredEndpoints: '暂无注册终端',
      driverUnknown: '驱动状态未知',
      remoteManagement: '远程管理',
      selectEndpoint: '选择一个终端',
      tabs: {
        files: '文件管理',
        processes: '进程管理',
        apps: '应用程序',
        startup: '自启动',
        sandbox: '隔离沙箱',
        shell: '命令终端',
        desktop: '远程桌面',
        accounts: '账号'
      },
      files: {
        pathPlaceholder: '选择磁盘或输入远程路径',
        hint: '双击文件夹或磁盘进入，右键项目执行操作。',
        noDrives: '未返回磁盘',
        notReady: '未就绪',
        freeOf: '{free} 可用，共 {total}',
        currentPath: '当前路径',
        newName: '新名称',
        renameTitle: '重命名远程项目',
        deleteTitle: '删除远程项目',
        deleteContent: '确认删除 {path}？'
      },
      processes: {
        searchPlaceholder: '搜索进程名、PID、路径或用户',
        hint: '右键进程可终止。',
        terminate: '终止',
        terminateTitle: '终止进程',
        terminateContent: '确认在 {target} 上终止 {name} ({pid})？'
      },
      apps: {
        installed: '{count} 个已安装应用',
        unnamed: '未命名应用',
        unknownPublisher: '未知发布者'
      },
      startup: {
        entries: '{count} 个自启动项'
      },
      sandbox: {
        title: '虚拟化隔离分析',
        subtitle: '样本只会在 Windows Sandbox / Hyper-V 边界内运行，宿主机不直接执行样本。',
        hardIsolation: '硬隔离',
        samplePath: '样本路径',
        samplePathPlaceholder: '例如 C:\\Users\\Public\\sample.exe',
        arguments: '启动参数',
        argumentsPlaceholder: '可选参数',
        timeout: '分析时长（秒）',
        options: '隔离选项',
        enableNetwork: '允许沙箱联网',
        copyDirectory: '复制同目录文件',
        closeWhenDone: '完成后关闭沙箱',
        run: '启动隔离分析',
        empty: '尚未运行隔离分析',
        pathRequired: '请输入样本路径。',
        invalidReport: '沙箱返回了无效报告。',
        boundary: '隔离边界',
        network: '网络',
        exitCode: '退出码',
        duration: '时间',
        columns: {
          severity: '等级',
          type: '类型',
          detail: '详情',
          time: '时间',
          signature: '签名',
          remote: '远端',
          local: '本地',
          state: '状态'
        },
        metrics: {
          behaviors: '行为',
          processes: '进程',
          network: '连接',
          artifacts: '文件'
        },
        sections: {
          behaviors: '危险行为',
          processes: '进程链',
          network: '网络连接',
          artifacts: '文件变化',
          output: '输出'
        },
        severity: {
          critical: '严重',
          high: '高危',
          medium: '中危',
          low: '低危',
          info: '信息'
        },
        risk: {
          critical: '严重风险',
          high: '高风险',
          medium: '中风险',
          low: '低风险',
          clean: '未见异常'
        }
      },
      shell: {
        connected: '已连接',
        stopped: '已停止',
        empty: '启动会话后，在下方输入命令并按 Enter 发送。',
        inputPlaceholder: '输入命令并按 Enter'
      },
      desktop: {
        title: '远程桌面截图',
        screenshotAlt: '远程桌面截图',
        noScreenshot: '尚未截图',
        invalidScreenshot: '终端返回了无效或被截断的截图数据。'
      },
      accounts: {
        username: '用户名',
        newPassword: '新密码',
        changePassword: '修改密码',
        passwordChanged: '密码修改任务已完成。'
      },
      activity: {
        title: '活动',
        empty: '当前会话暂无远程操作',
        queued: '已下发 {operation}',
        completed: '已完成 {operation}',
        renamed: '已重命名 {name}',
        deleted: '已删除 {name}',
        terminated: '已终止 {name} ({pid})',
        passwordChanged: '已修改 {username} 的密码',
        lockRequested: '已请求远程锁屏'
      },
      columns: {
        name: '名称',
        type: '类型',
        size: '大小',
        modified: '修改时间',
        folder: '文件夹',
        file: '文件',
        process: '进程',
        memory: '内存',
        started: '启动时间',
        path: '路径',
        location: '位置',
        command: '命令',
        state: '状态'
      },
      status: {
        online: '在线',
        offline: '离线'
      },
      operations: {
        file: {
          drives: '磁盘清单',
          list: '目录列表',
          delete: '文件删除',
          rename: '文件重命名'
        },
        process: {
          list: '进程清单',
          kill: '进程终止'
        },
        inventory: {
          installedApps: '应用清单',
          startupItems: '自启动清单'
        },
        cmd: {
          run: '远程命令'
        },
        terminal: {
          start: '终端启动',
          input: '终端输入',
          read: '终端输出读取',
          stop: '终端停止'
        },
        sandbox: {
          run: '隔离沙箱分析'
        },
        desktop: {
          screenshot: '桌面截图'
        },
        session: {
          lock: '锁屏'
        },
        user: {
          changePassword: '密码修改'
        }
      },
      errors: {
        selectEndpoint: '请先选择一个终端。',
        queueFailed: '无法下发远程操作。',
        operationFailed: '{operation} 失败。',
        timeout: '{operation} 等待终端响应超时。'
      }
    },
    sandbox: {
      eyebrow: 'Server Sandbox',
      title: '轻量沙箱分析',
      subtitle: '样本统一提交到 Server，在服务器侧隔离环境中执行分析，Agent 只负责发现和上传可疑 EXE。',
      serverOnly: '仅 Server 执行',
      upload: '上传样本',
      queue: '样本队列',
      analysis: '分析控制',
      analyze: '开始分析',
      report: '分析报告',
      empty: '暂无样本',
      noReport: '当前样本还没有报告',
      uploaded: '样本已提交到服务器。',
      started: '沙箱分析已启动。',
      deleted: '样本已删除。',
      deleteLogs: '删除日志',
      clearLogs: '清空日志',
      logsDeleted: '沙箱日志已删除。',
      logsCleared: '沙箱历史已清空。',
      exeOnly: '目前仅支持 EXE 样本。',
      webUploadReason: 'Web 管理端手动提交。',
      deleteTitle: '删除沙箱样本',
      deleteContent: '确认删除 {name} 的样本记录和服务器样本文件吗？',
      deleteLogsTitle: '删除沙箱日志',
      deleteLogsContent: '确认只删除 {name} 的沙箱报告和服务器运行日志吗？样本文件会保留，可重新分析。',
      clearLogsTitle: '清空沙箱历史',
      clearLogsContent: '确认清空所有沙箱运行目录、页面报告、样本记录和服务器样本文件吗？该操作后队列会清空。',
      arguments: '启动参数',
      argumentsPlaceholder: '可选参数',
      timeout: '分析时长（秒）',
      options: '隔离选项',
      enableNetwork: '允许沙箱联网',
      closeWhenDone: '完成后关闭沙箱',
      boundary: '隔离边界',
      network: '网络',
      exitCode: '退出码',
      duration: '时间',
      filters: {
        allStatus: '全部状态',
        allSources: '全部来源',
        host: '主机',
        search: '样本名、哈希、进程路径、签名者'
      },
      status: {
        queued: '待分析',
        running: '分析中',
        completed: '已完成',
        failed: '失败'
      },
      sources: {
        web: 'Web 提交',
        agent: 'Agent 上传'
      },
      metrics: {
        total: '样本总数',
        queued: '待分析',
        running: '分析中',
        completed: '已完成',
        failed: '失败'
      },
      reportMetrics: {
        behaviors: '行为',
        processes: '进程',
        network: '连接',
        artifacts: '文件',
        runtime: 'Runtime',
        kernel: '内核事件',
        services: '服务/驱动',
        tasks: '计划任务'
      },
      summary: {
        verdict: '分析结论',
        ready: '报告已生成',
        openReport: '查看完整报告',
        noSelection: '请选择一个沙箱样本。',
        noReport: '当前样本还没有生成报告。',
        queued: '样本已进入队列，尚未开始隔离执行。',
        running: '沙箱正在隔离执行样本，报告生成后会自动刷新。',
        failed: '沙箱分析失败，请查看错误信息和服务器日志。',
        invalid: '报告 JSON 无法解析，可能是旧版本报告或写入不完整。',
        completedNoReport: '样本状态为已完成，但当前记录没有报告内容；可重新分析，或检查服务器沙箱运行目录是否被清理。',
        timedOut: '样本执行超时，已保留沙箱遥测和隔离环境摘要。',
        nonZeroExit: '样本执行结束，退出码为 {exitCode}；仍保留本次行为遥测。',
        signals: '本次分析命中 {count} 条可观测信号，最高风险等级为 {severity}。',
        clean: '样本已执行完成，未观察到高危行为；建议结合样本来源和签名继续判定。'
      },
      attackFlow: {
        eyebrow: 'Attack Flow',
        title: '威胁故事线',
        active: '{count} 个阶段命中',
        processGraph: '进程关系',
        timeline: '行为时间线',
        empty: '暂无样本行为',
        entities: {
          processes: '进程',
          network: '网络',
          persistence: '持久化',
          artifacts: '文件'
        },
        stages: {
          launch: '样本启动',
          process: '进程链',
          apiMemory: 'API / 内存',
          network: '网络通信',
          persistence: '持久化',
          artifact: '文件 / 驱动'
        },
        details: {
          launch: '样本已进入隔离工作区',
          process: '命中 {count} 条子进程或高危命令链',
          apiMemory: '命中 {count} 条 Hook、syscall 或可执行内存行为',
          network: '命中 {count} 条远端连接或网络 API',
          persistence: '命中 {count} 条注册表、服务或计划任务变化',
          artifact: '命中 {count} 条落地文件、驱动或服务变化',
          idle: '未命中'
        }
      },
      columns: {
        sample: '样本',
        status: '状态',
        source: '来源',
        fileInfo: '文件信息',
        reason: '触发原因',
        submitted: '提交时间',
        host: '主机',
        path: '路径',
        error: '错误',
        severity: '等级',
        type: '类型',
        detail: '详情',
        time: '时间',
        process: '进程',
        signature: '签名',
        command: '命令',
        remote: '远端',
        local: '本地',
        state: '状态',
        size: '大小',
        action: '动作',
        target: '目标',
        statusText: '状态码',
        blocked: '阻断',
        change: '变化',
        service: '服务',
        task: '任务',
        sequence: '序号',
        operation: '操作',
        message: '消息'
      },
      sections: {
        behaviors: '危险行为',
        processes: '进程链',
        network: '网络连接',
        artifacts: '文件变化',
        runtime: 'API Hook / 内存遥测',
        kernel: '内核传感器',
        services: '服务与驱动变化',
        tasks: '计划任务变化',
        output: '输出'
      },
      telemetryMode: '遥测模式',
      runtimeHook: 'Runtime Hook',
      kernelSensor: '内核传感器',
      kernelPolicy: '内核策略',
      severity: {
        critical: '严重',
        high: '高危',
        medium: '中危',
        low: '低危',
        info: '信息'
      }
    },
    policy: {
      title: '策略管理',
      subtitle: '按扩展名绑定的中央策略会下发到所有已注册 DataProtector Agent。',
      centralOnline: '中央服务器在线',
      serverOffline: '服务器离线',
      tabs: {
        file: '文件策略',
        network: '网络防御',
        lateral: 'IPC / SMB 防御',
        userhook: '进程威胁感知',
        dlp: '截图 / 剪贴板防泄密',
        webshell: 'WebShell 防御',
        hashprotect: '反 Dump / Hash 防护',
        device: '设备管控'
      },
      file: {
        addTitle: '添加文件规则',
        inventory: '中央文件规则清单',
        ruleKind: '规则类型',
        extension: '扩展名',
        ruleValue: '规则值',
        addButton: '添加到中央策略',
        process: '进程',
        directory: '目录',
        excluded: '排除',
        processName: '进程名',
        processDirectory: '进程目录',
        excludedDirectory: '排除目录',
        kind: '类型',
        value: '规则值',
        added: '规则已添加到中央策略。',
        removed: '规则已从中央策略移除。',
        clearTitle: '清空文件规则',
        clearContent: '这会移除中央策略中的所有授信进程、授信目录和排除目录规则。',
        clearSuccess: '中央文件策略已清空。'
      },
      network: {
        quickActions: '快捷网络操作',
        inboundIcmp: '入站 ICMP',
        hardening: '终端加固',
        disablePing: '禁用入站 Ping',
        addTitle: '添加网络规则',
        inventory: '中央网络规则清单',
        kind: '规则类型',
        action: '动作',
        domain: '域名',
        remoteIp: '远端 IPv4 / CIDR',
        protocol: '协议',
        direction: '方向',
        localPort: '本地端口',
        remotePort: '远端端口',
        addButton: '添加网络规则',
        domains: '域名',
        ip: 'IP',
        icmp: 'ICMP',
        ruleId: '规则 ID',
        target: '目标',
        port: '端口',
        allow: '允许',
        any: '任意',
        outbound: '出站',
        inbound: '入站',
        both: '双向',
        allPingTargets: '* 表示所有 Ping 来源',
        cidrPlaceholder: '203.0.113.10 或 203.0.113.0/24',
        added: '网络规则已添加到中央策略。',
        removed: '网络规则已从中央策略移除。',
        pingAdded: '入站 Ping 禁用规则已添加。',
        clearTitle: '清空网络规则',
        clearContent: '这会移除中央策略中的所有网络允许/阻止规则。',
        clearSuccess: '中央网络策略已清空。'
      },
      lateral: {
        title: '横向移动防御策略',
        enforcement: '防护开关',
        enforcementDesc: '中央策略控制 SMB 可执行文件落地和 IPC 远程执行面。',
        smbCopy: 'SMB 可执行文件复制',
        smbCopyDesc: '阻止远程来源 SMB 文件操作创建、写入或重命名可执行载荷。',
        ipcTasks: 'IPC 计划任务',
        ipcTasksDesc: '阻止远程 Task Scheduler 命名管道访问和匹配的命令行启动模式。',
        ipcServices: 'IPC 服务创建',
        ipcServicesDesc: '阻止 Service Control Manager 命名管道滥用和远程服务命令模式。',
        remoteTools: '远程管理工具',
        remoteToolsDesc: '在执行前阻止 schtasks、at、sc、wmic 和 PowerShell Remoting 创建进程。',
        controls: '控制项：{count}/4',
        flags: '标志：{flags}',
        active: '生效：{count}',
        save: '保存横向防御',
        surfaces: '受保护横向移动面',
        smbStaging: 'SMB 可执行文件落地',
        smbStagingDesc: '阻止远程来源写入、创建或重命名通过 SMB 共享落地的可执行载荷。',
        ipcTaskScheduler: 'IPC 计划任务调度器',
        ipcTaskSchedulerDesc: '阻止 AT 和 Task Scheduler RPC 横向移动使用的命名管道访问。',
        ipcServiceControl: 'IPC 服务控制',
        ipcServiceControlDesc: '阻止远程服务创建和执行相关的服务控制管理器命名管道滥用。',
        remoteAdminLaunch: '远程管理工具启动',
        remoteAdminLaunchDesc: '在执行前阻止 schtasks、at、sc、wmic 和 PowerShell Remoting 启动模式。',
        saved: '横向移动防御策略已保存到中央策略。'
      },
      userhook: {
        title: '进程威胁感知策略',
        enforcement: '进程行为接管',
        enforcementDesc: '内核早鸟控制仅对未命中白名单的进程加载用户态行为监控 Runtime。',
        earlyProcess: '接管非白名单进程',
        earlyProcessDesc: '白名单命中的可信进程不接管；其它进程可在早期加载 Runtime 进行行为监控。',
        imageLoad: '敏感行为面监控',
        imageLoadDesc: '仅在已选中接管的进程内跟踪 ntdll、kernelbase、wininet、ws2_32、amsi 等敏感模块。',
        signedRuntime: '要求签名运行时',
        signedRuntimeDesc: '标记需要可信用户态运行时接管防护的进程。',
        auditOnly: '仅审计',
        auditOnlyDesc: '运行时推广验证期仅记录需要防护的动作。',
        blockUntrusted: '阻断高危 Hook 行为',
        blockUntrustedDesc: '运行时可阻断远程线程、跨进程写内存等高危行为。',
        systemProcesses: '包含系统进程',
        systemProcessesDesc: '将监控扩展到 PID 4 和系统启动面。',
        runtimeApiBehavior: '危险 API 行为监控',
        runtimeApiBehaviorDesc: '在已接管进程内监控远程线程、跨进程写内存、可执行内存和全局 Hook 等行为。',
        memoryScan: '内存异常扫描',
        memoryScanDesc: '周期扫描私有可执行页、RWX 页、手工映射 PE 和私有 syscall stub。',
        etwTamper: 'ETW 遥测防篡改',
        etwTamperDesc: '监控 EventWrite/EtwEventWrite 等遥测入口被 ret、跳转补丁或异常注销，用作行为链辅助判定。',
        controls: '控制项：{count}/9',
        active: '生效：{count}',
        excludedProcesses: '不接管进程名',
        excludedProcessPlaceholder: '每行一个进程，例如 chrome.exe',
        excludedPaths: '不接管完整路径',
        excludedPathPlaceholder: '每行一个完整路径，例如 C:\\Program Files\\TrustedApp\\app.exe',
        excludedDirectories: '不接管目录',
        excludedDirectoryPlaceholder: '每行一个目录，例如 C:\\Program Files\\TrustedApp',
        trustedSigners: '不接管签名主体',
        trustedSignerPlaceholder: '每行一个签名主体关键字，例如 Microsoft Corporation',
        runtimePath: '终端 Runtime 缓存路径',
        runtimePathPending: '保存策略后由 Agent 自动准备',
        save: '保存进程威胁感知',
        surfaces: '受保护的进程行为面',
        behaviorRules: '行为链判定规则',
        behaviorRulesDesc: '基于公开 EDR/Sigma/MITRE 思路，将原子行为按时间窗口、权重和阈值组合成恶意判定。',
        activeRules: '启用规则：{count}',
        ruleWindow: '窗口 {seconds}s',
        ruleThreshold: '阈值 {count}',
        ruleWeight: '权重 {score}',
        saved: '进程威胁感知策略已保存到中央策略。',
        surfacesList: {
          earlyTitle: '内核早鸟进程阶段',
          earlyDetail: '仅对白名单之外的进程请求 Runtime 接管。',
          imageTitle: '敏感 API 模块加载',
          imageDetail: '观察网络、凭据、UI 和脚本拦截常见的敏感 API 目标。',
          runtimeTitle: '签名运行时门禁',
          runtimeDetail: '将用户态防护组件与中央策略和签名要求绑定。',
          auditTitle: '度量推广模式',
          auditDetail: '在启用更强防护前，让终端上报将要接管的面。',
          apiTitle: '危险 API 行为链',
          apiDetail: '监控注入、跨进程写入、可执行内存和全局 Hook 等高危调用。',
          memoryTitle: '可执行内存异常',
          memoryDetail: '识别私有可执行、RWX、手工映射模块和 syscall stub 绕过迹象。',
          etwTitle: 'ETW 遥测完整性',
          etwDetail: '将 ETW patch、预补丁和异常注销作为防御规避信号。'
        }
      },      dlp: {
        title: '截图和剪贴板防泄密',
        enforcement: '终端 DLP 防护',
        enforcementDesc: '通过 Agent 控制剪贴板流转和常见截图入口。',
        clipboard: '剪贴板防护',
        clipboardDesc: '监听剪贴板更新，并按策略清除非可信进程写入的敏感对象。',
        screenshots: '截图防护',
        screenshotsDesc: '阻断常见截图热键，并清除截图进入剪贴板后的图片数据。',
        clipboardMode: '剪贴板模式',
        screenshotMode: '截图模式',
        modes: {
          audit: '仅审计',
          clear: '清除剪贴板',
          block: '阻断 / 清除'
        },
        text: '文本',
        images: '图片',
        files: '文件',
        clearScreenshotClipboard: '清除截图图片剪贴板',
        blockHotkeys: '阻断 PrintScreen 和 Win+Shift+S',
        trustedProcesses: '可信进程名',
        trustedProcessPlaceholder: '每行一个进程，例如 SnippingTool.exe',
        trustedDirectories: '可信进程目录',
        trustedDirectoryPlaceholder: '每行一个目录，例如 C:\\Program Files\\TrustedApp',
        activeControls: '生效控制：{count}',
        trustedEntries: '可信项：{count}',
        save: '保存 DLP 策略',
        saved: '截图和剪贴板防泄密策略已保存到中央策略。',
        surfaces: '受保护的数据流转面',
        surfacesList: {
          hotkeysTitle: '截图热键',
          hotkeysDetail: '在非可信会话创建屏幕位图前阻断 PrintScreen 和 Win+Shift+S。',
          clipboardImageTitle: '剪贴板图片',
          clipboardImageDetail: '识别 Bitmap、DIB、PNG、增强型图元文件等图片格式，并按策略清除。',
          clipboardTextTitle: '剪贴板文本',
          clipboardTextDetail: '控制纯文本、Unicode 文本、HTML 和 RTF 等文本格式。',
          clipboardFilesTitle: '剪贴板文件拖放',
          clipboardFilesDetail: '控制 CF_HDROP 文件转移数据，降低复制外泄路径。'
        }
      },
      webshell: {
        addTitle: '添加受保护 Web 目录',
        inventory: '受保护 Web 目录清单',
        webRoot: 'Web 根目录',
        addButton: '添加 WebShell 防御规则',
        directories: '目录',
        dangerEnabled: '危险阻断已启用',
        protectedDirectory: '受保护 Web 目录',
        detection: '检测',
        webScripts: 'Web 脚本',
        added: 'WebShell 防御规则已添加到中央策略。',
        removed: 'WebShell 防御规则已从中央策略移除。',
        clearTitle: '清空 WebShell 规则',
        clearContent: '这会移除中央策略中的所有受保护 Web 目录。',
        clearSuccess: '中央 WebShell 策略已清空。'
      },
      hashprotect: {
        title: 'Hash Dump 防护策略',
        enforcement: '防护开关',
        enforcementDesc: '中央策略版本控制 Agent 如何加固凭据 Dump 攻击面。',
        lsass: 'LSASS 句柄',
        lsassDesc: '阻止非授信进程获取内存 Dump 相关句柄权限。',
        credentialFiles: '凭据文件',
        credentialFilesDesc: '阻止访问 SAM、SYSTEM、SECURITY、NTDS 和卷影路径。',
        registryHives: '注册表 Hive',
        registryHivesDesc: '阻止对凭据 Hive 执行保存、还原和替换。',
        rawExtents: '原始磁盘范围',
        rawExtentsDesc: '仅拒绝与凭据文件磁盘范围重叠的原始读取。',
        features: '功能：{count}/4',
        assets: '资产：{count}',
        save: '保存反 Dump 策略',
        surfaces: '受保护面',
        saved: '反 Dump 策略已保存到中央策略。',
        assetsList: {
          lsassTitle: 'LSASS 进程内存',
          lsassDetail: '剥离非授信调用者的 VM_READ、DUP_HANDLE 等高危进程句柄权限。',
          filesTitle: '离线凭据存储',
          filesDetail: '阻止直接访问 SAM、SECURITY、SYSTEM、NTDS.dit、RegBack、Repair 和卷影副本别名。',
          registryTitle: '注册表 Hive 导出路径',
          registryDetail: '阻止对 HKLM SAM、SECURITY 和 SYSTEM 执行 Hive 保存、还原和替换。',
          rawTitle: '原始磁盘敏感范围',
          rawDetail: '允许普通原始卷读取，仅拒绝与敏感 Hive 和 NTDS 文件范围重叠的字节区间。'
        }
      },
      usbcrypt: {
        title: 'U 盘加密策略',
        enforcement: '透明 U 盘加密',
        enforcementDesc: '控制下发到终端 Agent 的可移动介质块加密工作流。',
        algorithm: '算法',
        publicAreaMb: '公开工具区 (MB)',
        toolArea: '{size} MB 公开区',
        keyMaterial: '密钥材料 ID',
        keyPlaceholder: 'central-key-id 或 wrapped-key 引用',
        requireAuthorization: '解锁前要求硬件授权',
        allowProvisioning: '允许 Agent 侧初始化流程',
        provisioning: 'Agent 初始化',
        save: '保存 U 盘加密策略',
        saved: 'U 盘加密策略已保存到中央策略。',
        packageReady: '运行包已就绪',
        packageMissing: '缺少运行包',
        packageTitle: 'Server 端运行包版本维护',
        packageDesc: '上传签名后的 U 盘解锁工具和驱动 zip。初始化时 Agent 会从 Server 下载该包，复制到 U 盘公开区，并设置隐藏和系统属性。',
        packageVersion: '运行包版本',
        packageVersionPlaceholder: '版本号，例如 2026.05.17',
        packageSize: '运行包大小',
        packageUploadedAt: '上传时间',
        packageUpload: '上传运行包',
        packageUploaded: 'U 盘运行包已上传。',
        packageRequired: '请先上传 U 盘运行包，再下发初始化任务。',
        initialize: '初始化加密',
        initializeTitle: '初始化 U 盘加密',
        initializeWarning:
          '这会向选中的 U 盘所在 Agent 下发初始化任务。Agent 会下载 Server 端维护的运行包，并把解锁信息写入 U 盘原始磁盘 metadata；解锁工具只有在密码正确时才会加载驱动。',
        initializePassword: '初始化密码',
        initializePasswordPlaceholder: '至少 8 个字符',
        confirmPassword: '确认密码',
        confirmPasswordPlaceholder: '再次输入初始化密码',
        confirmInitialize: '我确认该设备已授权执行 U 盘加密初始化。',
        initializeQueued: 'U 盘加密初始化任务已下发。',
        passwordMismatch: '请输入一致的密码并确认初始化。'
      },
      device: {
        discovered: '发现的可移动设备',
        addTitle: '添加可移动存储规则',
        inventory: '中央设备规则清单',
        pending: '待处理',
        authorized: '已授权',
        blocked: '已阻止',
        deviceId: '设备标识',
        insertionAccess: '插入访问',
        allowInsert: '允许插入',
        allowed: '已允许',
        allowWrite: '允许写入',
        writeAccess: '写入访问',
        rules: '规则',
        addButton: '添加设备规则',
        allStorage: '所有可移动存储',
        access: '访问',
        write: '写入',
        device: '设备',
        host: '主机',
        volumes: '卷',
        hardwareCode: '硬件码',
        status: '状态',
        seen: '发现',
        reset: '重置',
        added: '设备管控规则已添加到中央策略。',
        removed: '设备管控规则已从中央策略移除。',
        clearTitle: '清空设备管控规则',
        clearContent: '这会移除中央策略中的所有可移动存储访问和写入策略。',
        clearSuccess: '中央设备管控策略已清空。',
        authorizedWritable: '可移动设备已授权。',
        authorizedReadonly: '可移动设备已授权为只读。',
        blockedDevice: '可移动设备已阻止。',
        authorizationRemoved: '可移动设备授权已重置。',
        deleteInventoryTitle: '删除可移动设备',
        deleteInventoryContent: '确认删除 {code} 的可移动设备清单和授权吗？',
        inventoryDeleted: '可移动设备清单已删除。',
        removableStorage: '可移动存储',
        volumeCount: '{count} 个卷'
      },
      validation: {
        ruleKind: '规则类型不能为空',
        ruleValue: '规则值不能为空',
        extension: '扩展名不能为空',
        action: '动作不能为空',
        protocol: '协议不能为空',
        direction: '方向不能为空',
        domain: '域名不能为空',
        remoteAddress: '远端地址不能为空',
        protectedDirectory: '受保护 Web 目录不能为空',
        deviceId: '设备标识不能为空'
      }
    }
  }
};

export default local;
