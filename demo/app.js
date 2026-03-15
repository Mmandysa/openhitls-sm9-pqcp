const DEMO_IDENTITIES = {
  vehicle: "veh:oemA:vehicle:00012345",
  did: "dev:oemA:cn-sh:tbox:TBX00001",
  pidA: "pid:oemA:cn-sh:slot-20260315-0930:0099",
  pidB: "pid:oemA:cn-sh:slot-20260315-0945:0100",
  pidC: "pid:oemA:cn-sh:slot-20260315-1000:0101",
  rid: "rsu:cn-sh:pudong:0012",
  sid: "svc:aizonec:tsp-auth",
};

const layers = [
  {
    id: "object-plane",
    title: "对象主数据层",
    summary:
      "对象层只管理 vehicle_id、device_id 和 binding_id，不把业务属性直接等同于密码学身份。",
    contents: [
      "vehicle_id、device_id、rsu_id、service_id、binding_id",
      "支持一车换设备、一车多设备、设备返修复用",
      "为 PID -> DID -> device_id -> vehicle_id 追溯链保留业务落点",
    ],
    goals: ["对象解耦", "绑定可变", "追溯闭环"],
  },
  {
    id: "identity-plane",
    title: "身份层",
    summary:
      "身份层规划 DID、PID、RID、SID 的生命周期、作用域和版本，不让外部接入直接看到过多真实标识。",
    contents: [
      "DID 是长期设备身份",
      "PID 是短期伪名身份池",
      "RID / SID 分别面向 RSU 与云服务",
    ],
    goals: ["可分域", "可版本化", "隐私友好"],
  },
  {
    id: "auth-plane",
    title: "认证层",
    summary:
      "SM9 认证层负责证明身份真假，并通过 transcript 绑定上下文，防止消息被拆分、替换或重放。",
    contents: [
      "SERVER/CLIENT_CERT_VERIFY 对 transcript hash 做 SM9 签名",
      "车云与车路都做双向身份验证",
      "认证结果流向审计中心和冻结策略",
    ],
    goals: ["双向认证", "抗中间人", "抗身份冒用"],
  },
  {
    id: "pq-plane",
    title: "后量子密钥建立层",
    summary:
      "Scloud+ 只承担 KEM 角色，输出共享秘密并驱动主密钥导出，不直接负责长期身份可信。",
    contents: [
      "Scloud+ 公私钥版本管理",
      "ct_pq / ss_pq 封装与解封装",
      "双源模式可叠加 SM9 交换秘密",
    ],
    goals: ["抗量子会话秘密", "版本轮换", "高价值增强"],
  },
  {
    id: "session-plane",
    title: "会话保护层",
    summary:
      "SM3 负责 transcript 和 KDF，SM4-GCM 负责记录层密文，k_resume 支撑恢复能力。",
    contents: [
      "SM3 摘要、Finished、KDF",
      "SM4-GCM 保护 APPDATA",
      "k_resume、ticket 与区域恢复窗口",
    ],
    goals: ["机密性", "完整性", "低时延恢复"],
  },
  {
    id: "ops-plane",
    title: "运维与策略层",
    summary:
      "运维层负责 Root-KGC、Domain-KGC、PQ 参数中心、吊销中心、审计中心和策略服务。",
    contents: [
      "HSM、双人授权、不可导出与门限控制",
      "增量吊销、风险冻结与恢复",
      "参数版本升级与并行窗口管理",
    ],
    goals: ["分域治理", "吊销恢复", "参数升级"],
  },
];

const entities = {
  vehicle: {
    id: "vehicle",
    title: "Vehicle",
    subtitle: "业务主对象",
    badge: "object",
    x: 18,
    y: 86,
    summary:
      "Vehicle 是最终业务对象，不直接持有外部可见密码身份。它通过 vehicle_id 和绑定表连接到设备。",
    responsibilities: [
      "承载 vehicle_id 与业务状态",
      "支持换绑、过户、退役和审计追溯",
      "作为 PID 映射回落的最终对象",
    ],
    identities: ["vehicle_id", DEMO_IDENTITIES.vehicle, "binding_id"],
    keys: ["不直接持有 SM9 长期身份", "依赖设备与安全模组执行认证"],
    codeRefs: ["docs/pqtls_sm9_scloudplus_protocol_plan.md"],
  },
  device: {
    id: "device",
    title: "Device",
    subtitle: "T-Box / OBU",
    badge: "identity",
    x: 30,
    y: 60,
    summary:
      "Device 是主要接入主体，既可用 DID 长期接入云，也可用 PID 伪名接入 RSU。",
    responsibilities: [
      "发起 CLIENT_HELLO、CLIENT_KEM、FINISHED",
      "在 DID 与 PID 之间切换外部接入身份",
      "缓存 ticket、k_resume 和参数版本",
    ],
    identities: [DEMO_IDENTITIES.did, DEMO_IDENTITIES.pidA, DEMO_IDENTITIES.pidB],
    keys: ["SM9 签名私钥", "Scloud+ KEM 密钥对", "SM4 会话密钥"],
    codeRefs: ["src/client.c", "src/pqtls_handshake.c", "src/pqtls_record.c"],
  },
  se: {
    id: "se",
    title: "Security Module",
    subtitle: "SE / TEE / 安全 MCU",
    badge: "security",
    x: 18,
    y: 68,
    summary:
      "SE / TEE 托管 SM9 私钥、Scloud+ 私钥和恢复材料。演示工程用 PEM 文件，真实部署应放在安全硬件中。",
    responsibilities: [
      "托管 DID / PID 对应的 SM9 私钥",
      "托管设备侧 Scloud+ 私钥和 k_resume",
      "支持设备测量摘要和风险冻结",
    ],
    identities: ["hw_bind_id", "attestation digest", "secure profile"],
    keys: ["SK_SM9_sign(DID / PID)", "SK_Scloud+", "k_resume"],
    codeRefs: ["src/sm9_utils.c", "src/pqtls_sm9_auth.c"],
  },
};

const connections = [
  { id: "vehicle-device", from: "vehicle", to: "device", label: "binding" },
  { id: "device-se", from: "device", to: "se", label: "secure store" },
];

Object.assign(entities, {
  ra: {
    id: "ra",
    title: "RA",
    subtitle: "注册与审核",
    badge: "ops",
    x: 16,
    y: 18,
    summary:
      "RA 负责实名校验、产线审核和生产注入入口，是对象主数据和初始绑定的第一站。",
    responsibilities: [
      "生成 vehicle_id 与 device_id",
      "建立 vehicle_device_binding",
      "向 Domain-KGC 提交身份签发请求",
    ],
    identities: ["实名档案", "产线校验", "binding request"],
    keys: ["不直接持有业务会话密钥"],
    codeRefs: ["docs/pqtls_sm9_scloudplus_protocol_plan.md"],
  },
  "root-kgc": {
    id: "root-kgc",
    title: "Root-KGC",
    subtitle: "根信任中心",
    badge: "ops",
    x: 42,
    y: 12,
    summary:
      "Root-KGC 不直接给终端签私钥，只负责根授权、门限控制和根参数治理。",
    responsibilities: [
      "授权 Domain-KGC",
      "维护根参数和根审计",
      "要求 HSM 托管、双人授权和不可导出",
    ],
    identities: ["root domain", "root policy", "kgc authorization"],
    keys: ["SM9 主密钥", "根参数版本"],
    codeRefs: ["docs/pqtls_sm9_scloudplus_protocol_plan.md"],
  },
  "domain-kgc": {
    id: "domain-kgc",
    title: "Domain-KGC",
    subtitle: "分域 KGC",
    badge: "identity",
    x: 56,
    y: 22,
    summary:
      "Domain-KGC 按 OEM、区域或业务域签发 DID、PID、RID、SID，并控制其轮换与冻结。",
    responsibilities: [
      "发放 DID / PID / RID / SID",
      "维护 PID 池、有效期和状态标签",
      "把 PID -> DID 的追溯入口同步给云与审计中心",
    ],
    identities: ["domain_id", "PID pool", "identity registry"],
    keys: ["SM9 派生能力", "PID 策略"],
    codeRefs: ["src/setup_keys.c", "src/sm9_utils.c"],
  },
  "pq-center": {
    id: "pq-center",
    title: "PQ Center",
    subtitle: "PQ 参数中心",
    badge: "pq",
    x: 80,
    y: 16,
    summary:
      "PQ Center 管理 Scloud+ 参数版本、密钥轮换窗口和异常密钥吊销。",
    responsibilities: [
      "发布 KEM 参数版本",
      "推动云端和 RSU 的公钥轮换",
      "定义版本并行窗口与升级策略",
    ],
    identities: ["kem_version", "param_version", "grace window"],
    keys: ["PK / SK_Scloud+ version registry"],
    codeRefs: ["src/scloud_kem.c", "src/pqtls_keyschedule.c"],
  },
  cloud: {
    id: "cloud",
    title: "Cloud / TSP",
    subtitle: "云控与业务平台",
    badge: "service",
    x: 76,
    y: 54,
    summary:
      "Cloud / TSP 使用 SID 提供长期服务身份，负责高价值车云握手、追溯、吊销和策略下发。",
    responsibilities: [
      "返回 SERVER_HELLO、Scloud+ 公钥和 SID 签名",
      "对 ct_pq 解封装并导出 MSK、k_enc、k_mac、k_resume",
      "维护 PID 映射、风控、OTA 和恢复能力",
    ],
    identities: [DEMO_IDENTITIES.sid, "service_id", "policy_version"],
    keys: ["SK_SM9_sign(SID)", "PK / SK_Scloud+", "ticket secret"],
    codeRefs: ["src/server.c", "src/pqtls_handshake.c", "src/pqtls_keyschedule.c"],
  },
  audit: {
    id: "audit",
    title: "Audit Center",
    subtitle: "审计 / 吊销 / 风控",
    badge: "ops",
    x: 88,
    y: 34,
    summary:
      "审计中心沉淀 session_audit_log、吊销列表和合法追溯请求，是隐私与合规的收口点。",
    responsibilities: [
      "记录 identity_used、peer_identity、kem_alg、ticket_id",
      "同步冻结、吊销和恢复结果",
      "在合法场景下执行 PID -> DID -> device_id -> vehicle_id 追溯",
    ],
    identities: ["session_audit_log", "revocation delta", "freeze reason"],
    keys: ["不直接参与会话密钥导出", "维护吊销状态与日志签名"],
    codeRefs: ["docs/pqtls_sm9_scloudplus_protocol_plan.md"],
  },
  rsu: {
    id: "rsu",
    title: "RSU",
    subtitle: "路侧单元",
    badge: "edge",
    x: 60,
    y: 76,
    summary:
      "RSU 使用 RID 承担低时延近端认证和 ticket 恢复，对外看到的是 PID 而不是 DID。",
    responsibilities: [
      "返回 RID、区域策略和 Scloud+ 公钥",
      "解封装 ct_pq，派生短期会话密钥",
      "签发短期 ticket 并维护区域黑名单",
    ],
    identities: [DEMO_IDENTITIES.rid, "region_id", "ticket_id"],
    keys: ["SK_SM9_sign(RID)", "PK / SK_Scloud+", "ticket secret"],
    codeRefs: ["src/server.c", "src/pqtls_handshake.c"],
  },
});

connections.push(
  { id: "ra-domain", from: "ra", to: "domain-kgc", label: "registration" },
  { id: "root-domain", from: "root-kgc", to: "domain-kgc", label: "root auth" },
  { id: "domain-device", from: "domain-kgc", to: "device", label: "DID / PID issue" },
  { id: "domain-cloud", from: "domain-kgc", to: "cloud", label: "RID / SID / trace" },
  { id: "pq-cloud", from: "pq-center", to: "cloud", label: "KEM version" },
  { id: "pq-rsu", from: "pq-center", to: "rsu", label: "edge rotation" },
  { id: "cloud-audit", from: "cloud", to: "audit", label: "audit / revoke" },
  { id: "rsu-audit", from: "rsu", to: "audit", label: "delta blacklist" },
  { id: "device-cloud", from: "device", to: "cloud", label: "V2N" },
  { id: "device-rsu", from: "device", to: "rsu", label: "V2I" },
  { id: "cloud-rsu", from: "cloud", to: "rsu", label: "policy / ticket" },
);

const scenarios = [];

scenarios.push(
  {
    id: "provisioning",
    title: "生产注入与首次激活",
    tag: "registration",
    summary:
      "从 RA 审核、KGC 发放到 PQ 参数注入和首次激活，把对象主数据、身份和密钥一次接通。",
    meta: ["vehicle_id + device_id", "DID / PID / RID / SID", "首次激活"],
    focus: ["vehicle", "device", "se", "ra", "root-kgc", "domain-kgc", "pq-center", "cloud"],
    focusConnections: ["vehicle-device", "ra-domain", "root-domain", "domain-device", "domain-cloud", "pq-cloud"],
    baseline: [
      { label: "对象主键", value: "vehicle_id / device_id / binding_id" },
      { label: "长期身份", value: "DID / SID / RID 已规划" },
      { label: "伪名池", value: "PID-A / PID-B / PID-C 待激活" },
      { label: "PQ 版本", value: "scloudplus-v1 / param-2026.03" },
    ],
    steps: [
      {
        title: "RA 建立对象主数据与绑定关系",
        actors: ["ra", "vehicle", "device"],
        connections: ["vehicle-device", "ra-domain"],
        summary:
          "RA 创建 vehicle_id、device_id 和 binding_id，先把业务对象解耦，再进入密码学签发流程。",
        details: [
          "VIN 和设备序列号只用于审核，不直接作为长期对外认证身份。",
          "vehicle_device_binding 记录当前绑定和历史换绑窗口。",
          "RA 对产线、实名和设备来源做合法性校验。",
        ],
        security: ["对象与身份分离", "支持换绑与返修", "为追溯链预留入口"],
        snapshot: [
          { label: "vehicle_id", value: "veh-00012345" },
          { label: "device_id", value: "dev-0001" },
          { label: "binding", value: "current / active" },
        ],
        codeRefs: ["docs/pqtls_sm9_scloudplus_protocol_plan.md"],
      },
      {
        title: "Root-KGC 授权 Domain-KGC 发放身份",
        actors: ["root-kgc", "domain-kgc", "cloud"],
        connections: ["root-domain", "domain-cloud"],
        summary:
          "根 KGC 只做顶级授权，分域 KGC 负责 DID、PID、RID、SID 的实际签发。",
        details: [
          "DID 绑定设备长期身份，PID 以时间窗和域范围批量发放。",
          "RID 和 SID 供 RSU 与云服务在 SM9 认证中使用。",
          "PID -> DID 的映射不下发给普通 RSU。",
        ],
        security: ["分域隔离", "KGC 风险收敛", "支持合法追溯"],
        snapshot: [
          { label: "DID", value: DEMO_IDENTITIES.did },
          { label: "PID 池", value: "A / B / C 三个槽位" },
          { label: "SID / RID", value: "云端与 RSU ready" },
        ],
        codeRefs: ["src/setup_keys.c", "src/sm9_utils.c"],
      },
      {
        title: "PQ Center 下发 Scloud+ 参数与版本",
        actors: ["pq-center", "cloud", "rsu", "device"],
        connections: ["pq-cloud", "pq-rsu"],
        summary:
          "PQ 参数中心为设备、云和 RSU 准备 Scloud+ 参数、密钥版本和轮换窗口。",
        details: [
          "设备注入自身 KEM 密钥对，云和 RSU 准备服务端 KEM 公私钥。",
          "参数版本和过渡窗口进入策略中心，便于平滑升级。",
          "异常时可只吊销某个 KEM 版本。",
        ],
        security: ["后量子秘密来源独立", "参数可升级", "兼容并行窗口"],
        snapshot: [
          { label: "KEM", value: "Scloud+ / secbits=128" },
          { label: "version", value: "kem-v1" },
          { label: "window", value: "v1 active / v2 standby" },
        ],
        codeRefs: ["src/scloud_kem.c"],
      },
      {
        title: "安全模组注入私钥与根信任参数",
        actors: ["device", "se", "domain-kgc"],
        connections: ["device-se", "domain-device"],
        summary:
          "DID / PID 对应 SM9 私钥、Scloud+ 私钥和根信任参数进入 SE / TEE。",
        details: [
          "演示工程使用 PEM 文件，真实部署应转入 SE、TEE 或安全 MCU。",
          "安全模组同时保存 ticket 状态、恢复计数器和设备测量摘要。",
          "注入后设备具备首次激活所需的最小材料。",
        ],
        security: ["私钥不明文长期驻留", "支持设备证明", "便于风险冻结"],
        snapshot: [
          { label: "SM9 keys", value: "DID + PID slots" },
          { label: "Scloud+ SK", value: "sealed in SE" },
          { label: "trust", value: "root + domain params" },
        ],
        codeRefs: ["src/sm9_utils.c"],
      },
      {
        title: "设备首次激活并同步策略",
        actors: ["device", "cloud", "audit"],
        connections: ["device-cloud", "cloud-audit"],
        summary:
          "设备首次接入激活服务，换取时间同步、PID 策略、域配置和审计基线。",
        details: [
          "首次长期认证默认走 DID -> SID 链路。",
          "云侧下发 PID 轮换窗口、ticket 能力和区域策略。",
          "激活结果写入审计中心，为后续追溯留基线。",
        ],
        security: ["激活留痕", "策略下发", "恢复能力初始化"],
        snapshot: [
          { label: "activation", value: "success" },
          { label: "policy", value: "pid every 15 min" },
          { label: "audit", value: "baseline created" },
        ],
        codeRefs: ["src/pqtls_handshake.c"],
      },
    ],
  },
  {
    id: "vehicle-cloud",
    title: "车云高价值接入",
    tag: "did-sid",
    summary:
      "车端用 DID、云端用 SID 做 SM9 双向认证，Scloud+ 建立抗量子会话秘密，再由 SM4-GCM 保护业务流。",
    meta: ["DID ↔ SID", "高价值链路", "k_resume"],
    focus: ["device", "se", "cloud", "audit", "domain-kgc", "pq-center"],
    focusConnections: ["device-se", "device-cloud", "cloud-audit", "pq-cloud"],
    baseline: [
      { label: "接入身份", value: "DID -> SID" },
      { label: "会话模式", value: "SM9 auth + Scloud+ KEM" },
      { label: "恢复能力", value: "k_resume enabled" },
      { label: "记录层", value: "SM4-GCM / SM3 transcript" },
    ],
    steps: [
      {
        title: "车辆发起 M1",
        actors: ["device", "cloud"],
        connections: ["device-cloud"],
        summary: "设备以 DID 发起车云接入，请求高价值业务链路的混合认证。",
        formula: "V -> S\nDID || nonce_v || ts_v || alg_suite_list || domain_id",
        details: [
          "DID 暴露给云端没问题，因为车云本来就是长期管理链路。",
          "nonce_v、ts_v 和算法套件为抗重放与算法协商服务。",
          "domain_id 让云侧选择正确的 Domain-KGC 与策略版本。",
        ],
        security: ["抗重放", "域选择清晰", "为 transcript 绑定提供输入"],
        snapshot: [
          { label: "identity", value: "DID active" },
          { label: "nonce_v", value: "fresh" },
          { label: "suite", value: "SM9 + Scloud+ + SM4/SM3" },
        ],
        codeRefs: ["src/pqtls_handshake.c"],
      },
      {
        title: "云端返回 SID、策略与 SM9 服务签名",
        actors: ["cloud", "device"],
        connections: ["device-cloud", "pq-cloud"],
        summary:
          "云端下发 SID、nonce_s、策略和 Scloud+ 公钥，并对 M1 上下文做 SM9 签名。",
        formula:
          "M1 = DID || SID || nonce_v || nonce_s || ts_v || ts_s || policy || pk_scloud_s || alg_selected\nSig_SM9_S = Sign_SM9(SID, M1)",
        details: [
          "Scloud+ 公钥只承担 KEM 职责，服务身份真实性仍由 SM9 保证。",
          "策略可包含双源主密钥开关、ticket 恢复和设备证明要求。",
          "这一步对应仓库里的 SERVER_HELLO + SM9_CERT_VERIFY(server)。",
        ],
        security: ["服务身份真实性", "策略不可替换", "抗中间人"],
        snapshot: [
          { label: "SID", value: DEMO_IDENTITIES.sid },
          { label: "kem_pk", value: "cloud kem-v1" },
          { label: "policy", value: "high-value profile" },
        ],
        codeRefs: ["src/pqtls_handshake.c", "src/pqtls_sm9_auth.c"],
      },
      {
        title: "车辆验证 SID 与策略",
        actors: ["device", "se"],
        connections: ["device-se"],
        summary: "车端安全模组验证 SID、SM9 签名和策略，再决定是否继续执行 KEM。",
        details: [
          "验证失败时直接拒绝，不进入 KEM 封装阶段。",
          "若需要设备证明，可在本地加入 attestation 摘要。",
          "身份认证和 PQ 会话秘密建立在这里被清晰分层。",
        ],
        security: ["先认证后建密钥", "避免假服务端诱导封装", "策略绑定 transcript"],
        snapshot: [
          { label: "server auth", value: "verified" },
          { label: "attest", value: "optional" },
          { label: "decision", value: "proceed to encaps" },
        ],
        codeRefs: ["src/pqtls_sm9_auth.c"],
      },
      {
        title: "车辆封装共享秘密并回传 M2",
        actors: ["device", "cloud", "se"],
        connections: ["device-cloud", "device-se"],
        summary:
          "车端用云公钥执行 Scloud+ KEM，并用 DID 对 ct_pq 与上下文做 SM9 签名。",
        formula:
          "ct_pq, ss_pq = Encaps(pk_scloud_s)\nM2 = DID || SID || nonce_v || nonce_s || ts_v || ts_s || ct_pq || alg_selected || device_attest\nSig_SM9_V = Sign_SM9(DID, M2)",
        details: [
          "ss_pq 是后量子会话秘密来源，Sig_SM9_V 负责证明发起者身份与上下文一致。",
          "这一步对应仓库里的 CLIENT_KEM + SM9_CERT_VERIFY(client)。",
          "device_attest 可选，用于把设备测量摘要绑定到链路。",
        ],
        security: ["客户端身份真实性", "会话秘密抗量子", "上下文绑定"],
        snapshot: [
          { label: "ct_pq", value: "sent to cloud" },
          { label: "ss_pq", value: "sealed locally" },
          { label: "Sig_SM9_V", value: "DID signed" },
        ],
        codeRefs: ["src/scloud_kem.c", "src/pqtls_handshake.c"],
      },
      {
        title: "云端验签并解封装",
        actors: ["cloud", "audit"],
        connections: ["device-cloud", "cloud-audit"],
        summary:
          "云端先验证 DID 签名，再用 Scloud+ 私钥解封装，得到同一份 ss_pq。",
        details: [
          "验签失败、时间窗异常或风险冻结都会终止链路。",
          "解封装成功后云侧生成初始审计记录，标记 identity_used=DID。",
          "这一步是建立会话机密性的最后前置条件。",
        ],
        security: ["抗身份冒用", "风险冻结前置", "会话秘密对齐"],
        snapshot: [
          { label: "signature", value: "client verified" },
          { label: "decaps", value: "ss_pq recovered" },
          { label: "audit", value: "pre-session log open" },
        ],
        codeRefs: ["src/scloud_kem.c", "src/pqtls_sm9_auth.c"],
      },
      {
        title: "双方导出主密钥与派生密钥",
        actors: ["device", "cloud"],
        connections: ["device-cloud"],
        summary:
          "双方用 ss_pq、transcript_hash 和身份上下文导出 MSK，再派生会话保护材料。",
        formula:
          "MSK = KDF(ss_pq || transcript_hash || DID || SID || nonce_v || nonce_s)\nk_enc || k_mac || k_resume || k_export = Expand(MSK)",
        details: [
          "高价值模式可加上 ss_sm9，与 ss_pq 一起组成双源主密钥。",
          "k_resume 让区域内恢复与 ticket 恢复成为可能。",
          "仓库实现由 pqtls_derive_secrets() 和 Finished 校验驱动。",
        ],
        security: ["KDF 绑定 transcript", "恢复能力独立派生", "支持双源增强"],
        snapshot: [
          { label: "MSK", value: "derived" },
          { label: "k_enc / k_mac", value: "ready" },
          { label: "k_resume", value: "issued" },
        ],
        codeRefs: ["src/pqtls_keyschedule.c", "src/pqtls_crypto.c"],
      },
      {
        title: "Finished 确认并进入 SM4-GCM 会话",
        actors: ["device", "cloud", "audit"],
        connections: ["device-cloud", "cloud-audit"],
        summary:
          "双方交换 Finished，确认 transcript 与密钥完全一致，随后切换到 SM4-GCM 记录层。",
        formula:
          "FIN_S = MAC(k_mac, \"server finished\" || transcript_hash)\nFIN_V = MAC(k_mac, \"client finished\" || transcript_hash)",
        details: [
          "Finished 通过后，后续 APPDATA 都走 SM4-GCM。",
          "审计中心记录 session_id、auth_alg、kem_alg、result 与 ticket_id。",
          "这一步对应仓库里的 FINISHED 与 pqtls_record.c。",
        ],
        security: ["握手完整性确认", "抗中间人", "会话层切换完成"],
        snapshot: [
          { label: "session", value: "established" },
          { label: "record", value: "SM4-GCM live" },
          { label: "audit", value: "session_audit_log committed" },
        ],
        codeRefs: ["src/pqtls_handshake.c", "src/pqtls_record.c"],
      },
    ],
  },
);

const state = {
  scenarioId: "vehicle-cloud",
  stepIndex: -1,
  selection: { type: "entity", id: "device" },
  autoTimer: null,
};

const scenarioListEl = document.getElementById("scenarioList");
const layerChipsEl = document.getElementById("layerChips");
const nodesLayerEl = document.getElementById("nodesLayer");
const linkLayerEl = document.getElementById("linkLayer");
const stageStatusEl = document.getElementById("stageStatus");
const stepCardEl = document.getElementById("stepCard");
const selectionCardEl = document.getElementById("selectionCard");
const stateCardEl = document.getElementById("stateCard");
const timelineListEl = document.getElementById("timelineList");
const stepBtn = document.getElementById("stepBtn");
const autoBtn = document.getElementById("autoBtn");
const resetBtn = document.getElementById("resetBtn");

function getScenario() {
  return scenarios.find((scenario) => scenario.id === state.scenarioId);
}

function getStep() {
  const scenario = getScenario();
  return state.stepIndex >= 0 ? scenario.steps[state.stepIndex] : null;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function renderNodes() {
  nodesLayerEl.innerHTML = Object.values(entities)
    .map(
      (entity) => `
        <button
          type="button"
          class="node"
          data-entity-id="${entity.id}"
          style="left:${entity.x}%; top:${entity.y}%"
          aria-label="${escapeHtml(entity.title)}"
        >
          <h3>${escapeHtml(entity.title)}</h3>
          <p>${escapeHtml(entity.subtitle)}</p>
          <span class="entity-badge">${escapeHtml(entity.badge)}</span>
        </button>
      `,
    )
    .join("");

  nodesLayerEl.querySelectorAll(".node").forEach((nodeEl) => {
    nodeEl.addEventListener("click", () => {
      state.selection = { type: "entity", id: nodeEl.dataset.entityId };
      renderAll();
    });
  });
}

function renderLinks() {
  linkLayerEl.innerHTML = connections
    .map((connection) => {
      const from = entities[connection.from];
      const to = entities[connection.to];
      const labelX = ((from.x + to.x) / 2).toFixed(2);
      const labelY = ((from.y + to.y) / 2).toFixed(2);
      return `
        <g data-connection-id="${connection.id}">
          <line class="link" x1="${from.x}" y1="${from.y}" x2="${to.x}" y2="${to.y}"></line>
          <text class="link-label" x="${labelX}" y="${labelY}">${escapeHtml(connection.label)}</text>
        </g>
      `;
    })
    .join("");
}

function renderScenarioList() {
  const currentScenario = getScenario();
  scenarioListEl.innerHTML = scenarios
    .map(
      (scenario) => `
        <button type="button" class="scenario-card ${scenario.id === currentScenario.id ? "is-active" : ""}"
          data-scenario-id="${scenario.id}">
          <h3>${escapeHtml(scenario.title)}</h3>
          <p>${escapeHtml(scenario.summary)}</p>
          <div class="scenario-meta">
            ${scenario.meta.map((item) => `<span>${escapeHtml(item)}</span>`).join("")}
          </div>
        </button>
      `,
    )
    .join("");

  scenarioListEl.querySelectorAll(".scenario-card").forEach((button) => {
    button.addEventListener("click", () => {
      stopAuto();
      state.scenarioId = button.dataset.scenarioId;
      state.stepIndex = -1;
      state.selection = { type: "entity", id: getScenario().focus[0] };
      renderAll();
    });
  });
}

function renderLayerChips() {
  layerChipsEl.innerHTML = layers
    .map(
      (layer) => `
        <button type="button" class="layer-chip ${
          state.selection.type === "layer" && state.selection.id === layer.id ? "is-active" : ""
        }" data-layer-id="${layer.id}">
          <strong>${escapeHtml(layer.title)}</strong>
          <small>${escapeHtml(layer.goals.join(" / "))}</small>
        </button>
      `,
    )
    .join("");

  layerChipsEl.querySelectorAll(".layer-chip").forEach((button) => {
    button.addEventListener("click", () => {
      state.selection = { type: "layer", id: button.dataset.layerId };
      renderAll();
    });
  });
}

function renderStageStatus() {
  const scenario = getScenario();
  const step = getStep();
  const badges = [
    `场景: ${scenario.title}`,
    `步骤: ${state.stepIndex >= 0 ? `${state.stepIndex + 1}/${scenario.steps.length}` : `0/${scenario.steps.length}`}`,
    `身份: ${
      scenario.id === "vehicle-rsu"
        ? "PID / RID"
        : scenario.id === "vehicle-cloud"
          ? "DID / SID"
          : "多身份编排"
    }`,
  ];
  if (step) badges.push(`当前动作: ${step.title}`);
  stageStatusEl.innerHTML = badges.map((item) => `<span class="status-pill">${escapeHtml(item)}</span>`).join("");
}

function renderStepCard() {
  const scenario = getScenario();
  const step = getStep();
  if (!step) {
    stepCardEl.innerHTML = `
      <div class="step-card">
        <h3>${escapeHtml(scenario.title)}</h3>
        <p>${escapeHtml(scenario.summary)}</p>
        <ul class="bullet-list">
          ${scenario.meta.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}
        </ul>
      </div>
    `;
    return;
  }

  stepCardEl.innerHTML = `
    <div class="step-card">
      <h3>${escapeHtml(step.title)}</h3>
      <p>${escapeHtml(step.summary)}</p>
      ${step.formula ? `<pre class="formula">${escapeHtml(step.formula)}</pre>` : ""}
      <ul class="bullet-list">
        ${step.details.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}
      </ul>
      <div class="meta-row">
        <div class="meta-item">
          <strong>安全目标</strong>
          <div>${escapeHtml(step.security.join(" / "))}</div>
        </div>
        <div class="meta-item">
          <strong>实现落点</strong>
          <div>${escapeHtml(step.codeRefs.join(" · "))}</div>
        </div>
      </div>
    </div>
  `;
}

function renderSelectionCard() {
  if (state.selection.type === "layer") {
    const layer = layers.find((item) => item.id === state.selection.id);
    selectionCardEl.innerHTML = `
      <div class="selection-card">
        <h3>${escapeHtml(layer.title)}</h3>
        <p>${escapeHtml(layer.summary)}</p>
        <ul class="detail-list">
          ${layer.contents.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}
        </ul>
        <div class="meta-row">
          <div class="meta-item">
            <strong>本层目标</strong>
            <div>${escapeHtml(layer.goals.join(" / "))}</div>
          </div>
        </div>
      </div>
    `;
    return;
  }

  const entity = entities[state.selection.id];
  selectionCardEl.innerHTML = `
    <div class="selection-card">
      <h3>${escapeHtml(entity.title)}</h3>
      <p>${escapeHtml(entity.summary)}</p>
      <ul class="detail-list">
        ${entity.responsibilities.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}
      </ul>
      <div class="meta-row">
        <div class="meta-item">
          <strong>身份</strong>
          <div>${escapeHtml(entity.identities.join(" / "))}</div>
        </div>
        <div class="meta-item">
          <strong>密钥</strong>
          <div>${escapeHtml(entity.keys.join(" / "))}</div>
        </div>
        <div class="meta-item">
          <strong>代码映射</strong>
          <div>${escapeHtml(entity.codeRefs.join(" · "))}</div>
        </div>
      </div>
    </div>
  `;
}

function renderStateCard() {
  const scenario = getScenario();
  const step = getStep();
  const snapshot = step ? step.snapshot : scenario.baseline;
  stateCardEl.innerHTML = `
    <div class="state-card">
      <h3>${escapeHtml(step ? "步骤快照" : "场景基线")}</h3>
      <p>${
        step
          ? "当前步骤已经把以下身份、密钥或策略状态推进到位。"
          : "执行前的默认状态，用来观察后续步骤如何改变链路。"
      }</p>
      <div class="snapshot-grid">
        ${snapshot
          .map(
            (item) => `
              <div class="snapshot-item">
                <strong>${escapeHtml(item.label)}</strong>
                <div>${escapeHtml(item.value)}</div>
              </div>
            `,
          )
          .join("")}
      </div>
    </div>
  `;
}

function renderTimeline() {
  const scenario = getScenario();
  timelineListEl.innerHTML = scenario.steps
    .map((step, index) => {
      let statusClass = "is-pending";
      let statusLabel = "待执行";
      if (index < state.stepIndex) {
        statusClass = "is-done";
        statusLabel = "已完成";
      } else if (index === state.stepIndex) {
        statusClass = "is-current";
        statusLabel = "当前";
      }
      const badgeClass =
        statusLabel === "已完成" ? "status-done" : statusLabel === "当前" ? "status-current" : "status-pending";
      return `
        <button type="button" class="timeline-item ${statusClass}" data-step-index="${index}">
          <header>
            <h3>${index + 1}. ${escapeHtml(step.title)}</h3>
            <span class="${badgeClass}">${escapeHtml(statusLabel)}</span>
          </header>
          <p>${escapeHtml(step.summary)}</p>
        </button>
      `;
    })
    .join("");

  timelineListEl.querySelectorAll(".timeline-item").forEach((item) => {
    item.addEventListener("click", () => {
      state.stepIndex = Number(item.dataset.stepIndex);
      renderAll();
    });
  });
}

function updateTopologyState() {
  const scenario = getScenario();
  const step = getStep();
  const focusNodes = new Set(scenario.focus);
  const currentNodes = new Set(step ? step.actors : []);
  const selectedId = state.selection.type === "entity" ? state.selection.id : null;

  nodesLayerEl.querySelectorAll(".node").forEach((nodeEl) => {
    const id = nodeEl.dataset.entityId;
    nodeEl.classList.toggle("is-focused", focusNodes.has(id));
    nodeEl.classList.toggle("is-current", currentNodes.has(id));
    nodeEl.classList.toggle("is-selected", selectedId === id);
  });

  const focusConnections = new Set(scenario.focusConnections || []);
  const currentConnections = new Set(step ? step.connections : []);
  linkLayerEl.querySelectorAll("g").forEach((groupEl) => {
    const connectionId = groupEl.dataset.connectionId;
    const lineEl = groupEl.querySelector(".link");
    lineEl.classList.toggle("is-focused", focusConnections.has(connectionId));
    lineEl.classList.toggle("is-current", currentConnections.has(connectionId));
  });
}

function renderAutoButton() {
  autoBtn.classList.toggle("is-running", Boolean(state.autoTimer));
  autoBtn.textContent = state.autoTimer ? "停止自动演示" : "自动演示";
}

function stopAuto() {
  if (state.autoTimer) {
    window.clearInterval(state.autoTimer);
    state.autoTimer = null;
  }
  renderAutoButton();
}

function stepForward() {
  const scenario = getScenario();
  if (state.stepIndex < scenario.steps.length - 1) {
    state.stepIndex += 1;
    renderAll();
    if (state.stepIndex === scenario.steps.length - 1 && state.autoTimer) {
      window.setTimeout(() => {
        stopAuto();
      }, 800);
    }
  }
}

function renderAll() {
  renderScenarioList();
  renderLayerChips();
  renderStageStatus();
  renderStepCard();
  renderSelectionCard();
  renderStateCard();
  renderTimeline();
  updateTopologyState();
  renderAutoButton();
}

stepBtn.addEventListener("click", () => {
  stepForward();
});

autoBtn.addEventListener("click", () => {
  const scenario = getScenario();
  if (state.autoTimer) {
    stopAuto();
    return;
  }
  if (state.stepIndex >= scenario.steps.length - 1) {
    state.stepIndex = -1;
  }
  state.autoTimer = window.setInterval(() => {
    const activeScenario = getScenario();
    if (state.stepIndex >= activeScenario.steps.length - 1) {
      stopAuto();
      return;
    }
    stepForward();
  }, 2200);
  renderAutoButton();
});

resetBtn.addEventListener("click", () => {
  stopAuto();
  state.stepIndex = -1;
  renderAll();
});

scenarios.push(
  {
    id: "vehicle-rsu",
    title: "车路低时延接入",
    tag: "pid-rid",
    summary:
      "车端对外只暴露 PID，RSU 使用 RID 响应，首次握手后拿到 ticket，区域内恢复尽量避免重复重型认证。",
    meta: ["PID ↔ RID", "低时延", "ticket resume"],
    focus: ["device", "se", "rsu", "audit", "domain-kgc", "pq-center", "cloud"],
    focusConnections: ["device-se", "device-rsu", "rsu-audit", "cloud-rsu", "pq-rsu"],
    baseline: [
      { label: "对外身份", value: "PID only" },
      { label: "服务身份", value: "RID" },
      { label: "恢复机制", value: "short ticket" },
      { label: "目标", value: "区域内低时延" },
    ],
    steps: [
      {
        title: "车辆用 PID 发起区域接入",
        actors: ["device", "rsu"],
        connections: ["device-rsu"],
        summary: "车端对 RSU 仅暴露 PID，不发送长期 DID，减少长期轨迹关联风险。",
        formula: "V -> R\nPID || nonce_v || ts_v || alg_suite_list || region_id",
        details: [
          "PID 对应独立的 SM9 私钥和有效期。",
          "region_id 让 RSU 选择本区域策略和恢复窗口。",
          "跨域切换时可强制触发换名和重新握手。",
        ],
        security: ["伪名隐私", "抗重放", "区域策略选择"],
        snapshot: [
          { label: "PID", value: "slot-A active" },
          { label: "region", value: "cn-sh / pudong" },
          { label: "latency target", value: "low" },
        ],
        codeRefs: ["src/pqtls_handshake.c"],
      },
      {
        title: "RSU 返还 RID、策略和 Scloud+ 公钥",
        actors: ["rsu", "device"],
        connections: ["device-rsu", "pq-rsu"],
        summary:
          "RSU 用 RID 对首轮上下文签名，同时把自己的 KEM 公钥和本地策略发回车端。",
        formula:
          "M1 = PID || RID || nonce_v || nonce_s || ts_v || ts_s || pk_scloud_r || policy\nSig_SM9_R = Sign_SM9(RID, M1)",
        details: [
          "车端只需要验证 RID 合法性和 policy，不需要知道 RSU 背后的长期实名。",
          "策略可包含 ticket 生命周期、恢复次数上限和黑名单版本。",
          "Scloud+ 继续承担短期会话秘密来源。",
        ],
        security: ["服务身份真实性", "KEM 公钥绑定", "区域策略不可替换"],
        snapshot: [
          { label: "RID", value: DEMO_IDENTITIES.rid },
          { label: "ticket ttl", value: "120 s" },
          { label: "crl", value: "delta-17" },
        ],
        codeRefs: ["src/pqtls_sm9_auth.c", "src/scloud_kem.c"],
      },
      {
        title: "车辆用 PID 做 SM9 签名并封装 KEM",
        actors: ["device", "se", "rsu"],
        connections: ["device-rsu", "device-se"],
        summary: "车端验证 RID 之后，使用当前 PID 对 ct_pq 和上下文做 SM9 签名。",
        formula:
          "ct_pq, ss_pq = Encaps(pk_scloud_r)\nSig_SM9_V = Sign_SM9(PID, PID || RID || ct_pq || nonce_v || nonce_s || policy)",
        details: [
          "这让 RSU 只知道当前 PID 的真实性，而不知道它背后的 DID。",
          "ss_pq 继续提供抗量子会话秘密。",
          "若需设备证明，可把风险分数放入签名上下文。",
        ],
        security: ["伪名认证", "会话秘密抗量子", "上下文不可拆分"],
        snapshot: [
          { label: "current pid", value: "slot-A signed" },
          { label: "ct_pq", value: "sent to rsu" },
          { label: "privacy", value: "no DID exposed" },
        ],
        codeRefs: ["src/pqtls_handshake.c", "src/pqtls_sm9_auth.c"],
      },
      {
        title: "RSU 解封装并签发短期 ticket",
        actors: ["rsu", "audit", "cloud"],
        connections: ["device-rsu", "rsu-audit", "cloud-rsu"],
        summary: "RSU 解封装后立刻派生短期会话密钥，并在成功认证后下发区域内恢复 ticket。",
        details: [
          "ticket 绑定 PID、RID、region、policy_version 和 transcript_digest。",
          "黑名单版本和恢复计数器一并落到 RSU 缓存。",
          "必要时上送云端做区域一致性校验。",
        ],
        security: ["短有效期恢复", "恢复票据不可跨域滥用", "局部自治与中心协同"],
        snapshot: [
          { label: "session", value: "edge session ready" },
          { label: "ticket", value: "issued / bound to PID" },
          { label: "resume", value: "same region only" },
        ],
        codeRefs: ["src/pqtls_keyschedule.c", "docs/pqtls_sm9_scloudplus_protocol_plan.md"],
      },
      {
        title: "区域内恢复避免重复重型握手",
        actors: ["device", "rsu"],
        connections: ["device-rsu"],
        summary: "后续短时间内再次接入同区域 RSU 时，可使用 ticket + transcript digest 恢复会话。",
        details: [
          "若 ticket 超时、跨域、风险状态变化或 KEM 版本升级，则强制完整握手。",
          "恢复只优化时延，不替代吊销校验和策略检查。",
          "车路链路因此能兼顾低时延与风控。",
        ],
        security: ["低时延", "恢复可控", "策略失效即回退完整握手"],
        snapshot: [
          { label: "resume mode", value: "enabled" },
          { label: "fallback", value: "full handshake on risk" },
          { label: "seq", value: "new record window" },
        ],
        codeRefs: ["src/pqtls_record.c", "docs/pqtls_sm9_scloudplus_protocol_plan.md"],
      },
    ],
  },
  {
    id: "pid-rotation",
    title: "PID 轮换与隐私保护",
    tag: "privacy",
    summary:
      "通过 PID 池、时间窗、跨域切换和风险事件，让 RSU 只能看到短期身份，而云端仍保留合法追溯能力。",
    meta: ["PID pool", "privacy", "traceability"],
    focus: ["device", "se", "domain-kgc", "cloud", "rsu", "audit"],
    focusConnections: ["domain-device", "device-se", "device-rsu", "cloud-audit", "domain-cloud"],
    baseline: [
      { label: "当前 PID", value: "slot-A active" },
      { label: "备选 PID", value: "slot-B / slot-C standby" },
      { label: "映射", value: "PID -> DID -> device_id -> vehicle_id" },
      { label: "触发条件", value: "时间窗 / 跨域 / 风险" },
    ],
    steps: [
      {
        title: "Domain-KGC 预下发 PID 池",
        actors: ["domain-kgc", "device", "cloud"],
        connections: ["domain-device", "domain-cloud"],
        summary: "设备在上线前就拿到一组短期 PID 与对应 SM9 私钥，云端保留映射索引。",
        details: [
          "PID 池记录有效时间窗、域范围、状态标签和风险级别。",
          "云侧知道 PID 背后的 DID，但 RSU 无权拿到该映射。",
          "同一设备可预置多个时间片，减少高频在线申请成本。",
        ],
        security: ["减少在线依赖", "隐私与追溯兼顾", "适合高频接入"],
        snapshot: [
          { label: "PID-A", value: "09:30 active" },
          { label: "PID-B", value: "09:45 standby" },
          { label: "PID-C", value: "10:00 standby" },
        ],
        codeRefs: ["src/setup_keys.c", "src/sm9_utils.c"],
      },
      {
        title: "时间窗到达或跨域切换触发换名",
        actors: ["device", "se", "rsu"],
        connections: ["device-se", "device-rsu"],
        summary: "设备根据时间槽、区域变化或风险事件，把对外身份从旧 PID 切到新 PID。",
        details: [
          "切换动作由安全模组执行，旧 PID 进入 draining 或 frozen 状态。",
          "对外链路重新使用新 PID 做 SM9 认证。",
          "RSU 看到的是全新的短期身份，无法直接关联到旧会话。",
        ],
        security: ["打断长期轨迹关联", "最小暴露", "换名受控"],
        snapshot: [
          { label: "active", value: "PID-B" },
          { label: "old pid", value: "PID-A draining" },
          { label: "region", value: "new policy applied" },
        ],
        codeRefs: ["docs/pqtls_sm9_scloudplus_protocol_plan.md"],
      },
      {
        title: "云端保留合法追溯链",
        actors: ["cloud", "audit"],
        connections: ["cloud-audit", "domain-cloud"],
        summary: "云侧和审计中心仍然可以在合法场景下把 PID 还原到设备和车辆对象。",
        formula: "PID -> DID -> device_id -> vehicle_id",
        details: [
          "这一映射不会下发给普通 RSU，也不会出现在公开链路里。",
          "审计中心会把访问映射的行为留痕。",
          "因此方案既能避免长期跟踪，也能满足追责要求。",
        ],
        security: ["合法可追溯", "非授权不可关联", "访问留痕"],
        snapshot: [
          { label: "mapping", value: "backend only" },
          { label: "visibility", value: "RSU cannot resolve" },
          { label: "audit", value: "trace request logged" },
        ],
        codeRefs: ["docs/pqtls_sm9_scloudplus_protocol_plan.md"],
      },
      {
        title: "风险事件可冻结单个 PID 而不影响 DID",
        actors: ["audit", "cloud", "device"],
        connections: ["cloud-audit", "device-se"],
        summary: "当某个 PID 暴露或异常时，可先冻结该 PID，再补发新 PID，而不必直接废掉 DID。",
        details: [
          "风控粒度更细，不会把长期身份和短期伪名绑死。",
          "设备收到冻结通知后会立即切换到新 PID 或回退到完整握手。",
          "老 ticket 同时作废，避免伪名失效后还能恢复旧会话。",
        ],
        security: ["细粒度冻结", "最小影响面", "票据同步失效"],
        snapshot: [
          { label: "PID-A", value: "frozen" },
          { label: "PID-B", value: "new active" },
          { label: "ticket", value: "reissued" },
        ],
        codeRefs: ["docs/pqtls_sm9_scloudplus_protocol_plan.md"],
      },
    ],
  },
  {
    id: "key-rotation",
    title: "密钥更新、吊销与恢复",
    tag: "ops",
    summary:
      "运维平面负责 Scloud+ 版本升级、DID / PID / RID / SID 冻结、ticket 作废和审计恢复。",
    meta: ["rotation", "revocation", "recovery"],
    focus: ["pq-center", "cloud", "rsu", "domain-kgc", "audit", "device", "se"],
    focusConnections: ["pq-cloud", "pq-rsu", "cloud-audit", "rsu-audit", "domain-cloud", "device-se", "cloud-rsu"],
    baseline: [
      { label: "旧版本", value: "kem-v1 active" },
      { label: "新版本", value: "kem-v2 staged" },
      { label: "吊销对象", value: "PID / RID / SID / KEM version" },
      { label: "恢复策略", value: "full handshake or reissue" },
    ],
    steps: [
      {
        title: "PQ Center 发布新 KEM 版本并打开并行窗口",
        actors: ["pq-center", "cloud", "rsu"],
        connections: ["pq-cloud", "pq-rsu"],
        summary: "PQ 参数中心先把新版本推到云和 RSU，旧版本保持短暂并行，避免整体闪断。",
        details: [
          "并行窗口让在线设备能够分批完成完整握手升级。",
          "策略可标记哪些业务必须立即切换到新版本。",
          "旧版本进入 deprecating 状态，为后续吊销做准备。",
        ],
        security: ["平滑升级", "版本可审计", "不牺牲可用性"],
        snapshot: [
          { label: "kem-v1", value: "deprecating" },
          { label: "kem-v2", value: "preferred" },
          { label: "window", value: "24h overlap" },
        ],
        codeRefs: ["src/scloud_kem.c"],
      },
      {
        title: "云端与 RSU 强制高价值会话重新握手",
        actors: ["cloud", "rsu", "device"],
        connections: ["device-cloud", "device-rsu", "cloud-rsu"],
        summary: "对高风险或高价值业务，旧 ticket 被强制失效，要求设备用新 KEM 版本重新握手。",
        details: [
          "重新握手时会重新生成 ct_pq、ss_pq 和 k_resume。",
          "区域内恢复被暂时关闭，直到新版本握手成功。",
          "云端和 RSU 都能通过策略切换这一行为。",
        ],
        security: ["旧密钥快速淘汰", "高价值链路优先升级", "恢复能力重新绑定"],
        snapshot: [
          { label: "ticket", value: "invalidate all v1" },
          { label: "handshake", value: "full re-auth required" },
          { label: "k_resume", value: "rotate" },
        ],
        codeRefs: ["src/pqtls_handshake.c", "src/pqtls_keyschedule.c"],
      },
      {
        title: "Domain-KGC 与审计中心执行身份吊销",
        actors: ["domain-kgc", "audit", "cloud", "rsu"],
        connections: ["domain-cloud", "cloud-audit", "rsu-audit"],
        summary: "若某个 PID、RID、SID 或 KEM 版本异常，系统同步在线状态、增量黑名单和冻结原因。",
        details: [
          "高价值场景实时查状态，普通场景使用短有效期加增量吊销列表。",
          "RSU 缓存区域黑名单，云端维护全局冻结与恢复指令。",
          "吊销结果附带原因和生效时间。",
        ],
        security: ["快速失效", "局部缓存", "全局一致性"],
        snapshot: [
          { label: "revocation", value: "RID-0012 blocked" },
          { label: "delta crl", value: "sync to edge" },
          { label: "status", value: "online check enabled" },
        ],
        codeRefs: ["docs/pqtls_sm9_scloudplus_protocol_plan.md"],
      },
      {
        title: "设备执行恢复策略或重新注入",
        actors: ["device", "se", "cloud"],
        connections: ["device-se", "device-cloud"],
        summary: "设备根据风控结果选择 ticket 恢复、PID 池重发或重新发 DID / Scloud+ 密钥。",
        details: [
          "若只是 PID 失效，可直接切换新 PID 并重签票据。",
          "若长期 DID 或设备密钥异常，则必须重新激活或换绑。",
          "恢复动作结束后，新状态重新进入审计闭环。",
        ],
        security: ["恢复分层", "长期与短期身份解耦", "避免不必要换绑"],
        snapshot: [
          { label: "recovery", value: "PID pool refill" },
          { label: "fallback", value: "re-activation if DID revoked" },
          { label: "status", value: "healthy again" },
        ],
        codeRefs: ["src/setup_keys.c", "docs/pqtls_sm9_scloudplus_protocol_plan.md"],
      },
      {
        title: "审计中心完成闭环归档",
        actors: ["audit", "cloud"],
        connections: ["cloud-audit"],
        summary: "每次版本升级、吊销和恢复都会形成可追踪链路，便于后续参数升级复盘。",
        details: [
          "审计中心记录 session lineage、key version、identity_used 和处理结果。",
          "策略服务据此调整下一轮 PID 周期、ticket 有效期和 KEM 并行窗口。",
          "这让方案不仅能建链，还能长期可运维。",
        ],
        security: ["可复盘", "可追责", "支持后续策略优化"],
        snapshot: [
          { label: "lineage", value: "session history linked" },
          { label: "policy", value: "next rotation tuned" },
          { label: "archive", value: "closed" },
        ],
        codeRefs: ["docs/pqtls_sm9_scloudplus_protocol_plan.md"],
      },
    ],
  },
);

renderNodes();
renderLinks();
renderAll();
