const general = {
  home: "\u9996\u9801",
  load: "\u8F09\u5165",
  open: "\u958B\u555F",
  close: "\u95DC\u9589",
  yes: "\u662F",
  no: "\u5426",
  ok: "OK",
  and: "\u548C",
  or: "\u6216",
  add: "\u65B0\u589E",
  edit: "\u7DE8\u8F2F",
  remove: "\u79FB\u9664",
  save: "\u5132\u5B58",
  cancel: "\u53D6\u6D88",
  submit: "\u63D0\u4EA4",
  create: "\u5EFA\u7ACB",
  insert: "\u63D2\u5165",
  "delete": "\u522A\u9664",
  update: "\u66F4\u65B0",
  rename: "\u91CD\u65B0\u547D\u540D",
  reload: "\u91CD\u65B0\u8F09\u5165",
  reset: "\u91CD\u8A2D",
  install: "\u5B89\u88DD",
  show: "\u986F\u793A",
  hide: "\u96B1\u85CF",
  showAll: "\u986F\u793A\u6240\u6709",
  hideAll: "\u5168\u90E8\u96B1\u85CF",
  showMore: "\u986F\u793A\u66F4\u591A",
  showOptions: "\u986F\u793A\u9078\u9805",
  hideOptions: "\u96B1\u85CF\u9078\u9805",
  showMenu: "\u986F\u793A\u9078\u55AE",
  hideMenu: "\u96B1\u85CF\u9078\u55AE",
  addAll: "\u5168\u90E8\u65B0\u589E",
  removeAll: "\u5168\u90E8\u79FB\u9664",
  signUp: "\u8A3B\u518A",
  signIn: "\u767B\u5165",
  signOut: "\u767B\u51FA",
  required: "\u5FC5\u586B",
  preferred: "\u9996\u9078",
  mandatory: "\u5F37\u5236\u7684",
  loading: "\u8F09\u5165\u4E2D...",
  title: "\u6A19\u984C",
  upload: "\u4E0A\u50B3",
  download: "\u4E0B\u8F09",
  "default": "\u9810\u8A2D",
  more: "\u66F4\u591A",
  less: "\u8F03\u5C11",
  event: "\u4E8B\u4EF6",
  condition: "\u689D\u4EF6",
  after: "\u5F8C",
  before: "\u524D",
  search: "\u641C\u5C0B",
  notification: "\u901A\u77E5",
  reference: "\u53C3\u8003",
  "function": "\u529F\u80FD"
};
const objects = {
  project: "\u9805\u76EE",
  projects: "\u9805\u76EE",
  table: "\u8868\u683C",
  tables: "\u8868\u683C",
  field: "\u6B04\u4F4D",
  fields: "\u6B04\u4F4D",
  column: "\u5217",
  columns: "\u5217",
  page: "\u9801",
  pages: "\u9801",
  record: "\u8A18\u9304",
  records: "\u8A18\u9304",
  webhook: "Webhook",
  webhooks: "Webhook",
  view: "\u6AA2\u8996\u8868",
  views: "\u6AA2\u8996\u8868",
  viewType: {
    grid: "\u7DB2\u683C",
    gallery: "\u5716\u5EAB",
    form: "\u8868\u55AE",
    kanban: "\u770B\u677F",
    calendar: "\u65E5\u66C6"
  },
  user: "\u4F7F\u7528\u8005",
  users: "\u4F7F\u7528\u8005",
  role: "\u89D2\u8272",
  roles: "\u89D2\u8272",
  roleType: {
    owner: "\u6240\u6709\u8005",
    creator: "\u5275\u9020\u8005",
    editor: "\u7DE8\u8F2F",
    commenter: "\u8A55\u8AD6\u8005",
    viewer: "\u6AA2\u8996\u8005"
  }
};
const datatype = {
  ID: "ID",
  ForeignKey: "\u5916\u9470\u5319",
  SingleLineText: "\u55AE\u884C\u6587\u672C",
  LongText: "\u9577\u7BC7\u6587\u7AE0",
  Attachment: "\u9644\u4EF6",
  Checkbox: "\u6838\u53D6\u65B9\u584A",
  MultiSelect: "\u591A\u9078",
  SingleSelect: "\u55AE\u9078",
  Collaborator: "\u5408\u4F5C\u8005",
  "Date": "\u65E5\u671F",
  Year: "\u5E74",
  Time: "\u6642\u9593",
  PhoneNumber: "\u96FB\u8A71\u865F\u78BC",
  Email: "\u96FB\u5B50\u90F5\u4EF6",
  URL: "\u7DB2\u5740",
  "Number": "\u6578\u5B57",
  Decimal: "\u5341\u9032\u5236",
  Currency: "\u8CA8\u5E63",
  Percent: "\u767E\u5206",
  Duration: "\u671F\u9593",
  Rating: "\u8A55\u5206",
  Formula: "\u516C\u5F0F",
  Rollup: "\u6372\u8D77",
  Count: "\u6578\u6578",
  Lookup: "\u62AC\u982D",
  DateTime: "\u65E5\u671F\u6642\u9593",
  CreateTime: "\u5275\u5EFA\u6642\u9593",
  LastModifiedTime: "\u6700\u5F8C\u4FEE\u6539\u6642\u9593",
  AutoNumber: "\u81EA\u52D5\u7DE8\u865F",
  Barcode: "\u689D\u78BC",
  Button: "\u6309\u9215",
  Password: "\u5BC6\u78BC",
  relationProperties: {
    noAction: "\u6C92\u6709\u4EFB\u4F55\u884C\u52D5",
    cascade: "\u7D1A\u806F",
    restrict: "\u56B4\u683C",
    setNull: "\u8A2D\u7F6E null",
    setDefault: "\u9ED8\u8A8D\u8A2D\u7F6E"
  }
};
const filterOperation = {
  isEqual: "\u5B8C\u5168\u4E00\u81F4",
  isNotEqual: "\u5B8C\u5168\u4E0D\u4E00\u81F4",
  isLike: "\u90E8\u5206\u4E00\u81F4",
  "isNot like": "\u90E8\u5206\u4E0D\u4E00\u81F4",
  isEmpty: "\u662F\u7A7A\u7684",
  isNotEmpty: "\u4E0D\u662F\u7A7A\u7684",
  isNull: "\u4E00\u7247\u7A7A\u767D",
  isNotNull: "\u4E0D\u662F\u7A7A\u865B"
};
const title = {
  newProj: "\u5EFA\u7ACB\u65B0\u5C08\u6848",
  myProject: "\u6211\u7684\u5C08\u6848",
  formTitle: "\u8868\u683C\u6A19\u984C",
  collabView: "\u5408\u4F5C\u8996\u5716",
  lockedView: "\u9396\u5B9A\u8996\u5716",
  personalView: "\u500B\u4EBA\u89C0",
  appStore: "\u61C9\u7528\u7A0B\u5F0F\u5546\u5E97",
  teamAndAuth: "\u5718\u968A\u548C\u8A8D\u8B49",
  rolesUserMgmt: "\u89D2\u8272\u548C\u4F7F\u7528\u8005\u7BA1\u7406",
  userMgmt: "\u4F7F\u7528\u8005\u7BA1\u7406",
  apiTokenMgmt: "API \u6B0A\u6756\u7BA1\u7406",
  rolesMgmt: "\u89D2\u8272\u7BA1\u7406",
  projMeta: "\u5C08\u6848\u4E2D\u7E7C\u8CC7\u6599",
  metaMgmt: "\u4E2D\u7E7C\u8CC7\u6599\u7BA1\u7406",
  metadata: "\u4E2D\u7E7C\u8CC7\u6599",
  exportImportMeta: "\u532F\u51FA/\u532F\u5165\u4E2D\u7E7C\u8CC7\u6599",
  uiACL: "UI \u5B58\u53D6\u63A7\u5236",
  metaOperations: "\u4E2D\u7E7C\u8CC7\u6599\u64CD\u4F5C",
  audit: "\u7A3D\u6838",
  auditLogs: "\u7A3D\u6838\u8A18\u9304",
  sqlMigrations: "SQL \u9077\u79FB",
  dbCredentials: "\u8CC7\u6599\u5EAB\u6191\u8B49",
  advancedParameters: "SSL \u53CA\u9032\u968E\u53C3\u6578",
  headCreateProject: "\u5EFA\u7ACB\u65B0\u5C08\u6848\uFF5CNocoDB",
  headLogin: "\u767B\u5165\uFF5CNocoDB",
  resetPassword: "\u91CD\u8A2D\u5BC6\u78BC",
  teamAndSettings: "\u5718\u968A & \u8A2D\u5B9A",
  apiDocs: "API \u8AAA\u660E\u6587\u4EF6",
  importFromAirtable: "Import From Airtable"
};
const labels = {
  notifyVia: "\u900F\u904E...\u901A\u77E5",
  projName: "\u9805\u76EE\u540D",
  tableName: "\u8868\u540D\u7A31",
  viewName: "\u67E5\u770B\u540D\u7A31",
  viewLink: "\u67E5\u770B\u93C8\u63A5",
  columnName: "\u5217\u540D\u7A31",
  columnType: "\u5217\u985E\u578B",
  roleName: "\u89D2\u8272\u540D\u7A31",
  roleDescription: "\u89D2\u8272\u63CF\u8FF0",
  databaseType: "\u9375\u5165\u6578\u64DA\u5EAB",
  lengthValue: "\u9577\u5EA6/\u503C",
  dbType: "\u8CC7\u6599\u5EAB\u985E\u578B",
  sqliteFile: "SQLite \u6A94\u6848",
  hostAddress: "\u4E3B\u6A5F\u4F4D\u5740",
  port: "\u9023\u7DDA\u57E0\u865F\u78BC",
  username: "\u4F7F\u7528\u8005\u540D\u7A31",
  password: "\u5BC6\u78BC",
  schemaName: "Schema name",
  action: "\u884C\u52D5",
  actions: "\u884C\u52D5",
  operation: "\u64CD\u4F5C",
  operationType: "\u64CD\u4F5C\u985E\u578B",
  operationSubType: "\u64CD\u4F5C\u5B50\u985E\u578B",
  description: "\u63CF\u8FF0",
  authentication: "\u9A57\u8B49",
  token: "\u6B0A\u6756",
  where: "\u5728\u54EA\u88E1",
  cache: "\u7DE9\u5B58",
  chat: "\u804A\u5929",
  email: "\u96FB\u5B50\u90F5\u4EF6",
  storage: "\u8CAF\u5B58",
  uiAcl: "UI-ACL",
  models: "\u6977\u6A21",
  syncState: "\u540C\u6B65\u72C0\u614B",
  created: "\u5DF2\u5EFA\u7ACB",
  sqlOutput: "SQL \u8F38\u51FA",
  addOption: "\u65B0\u589E\u9078\u9805",
  aggregateFunction: "\u532F\u7E3D\u529F\u80FD",
  dbCreateIfNotExists: "\u8CC7\u6599\u5EAB\uFF1A\u4E0D\u5B58\u5728\u5247\u5EFA\u7ACB",
  clientKey: "\u7528\u6236\u7AEF\u91D1\u9470",
  clientCert: "\u7528\u6236\u7AEF\u6191\u8B49",
  serverCA: "\u4F3A\u670D\u5668 CA",
  requriedCa: "\u5FC5\u586B - CA",
  requriedIdentity: "\u5FC5\u586B - IDENTITY",
  inflection: {
    tableName: "\u5C48\u6298 - \u8868\u683C\u540D\u7A31",
    columnName: "\u5C48\u6298 - \u6B04\u4F4D\u540D\u7A31"
  },
  community: {
    starUs1: "\u5728 Github \u4E0A",
    starUs2: "\u5E6B\u6211\u5011\u6309\u8B9A",
    bookDemo: "\u9810\u8A02\u514D\u8CBB Demo",
    getAnswered: "\u89E3\u60D1\u60A8\u7684\u554F\u984C",
    joinDiscord: "\u52A0\u5165 Discord",
    joinCommunity: "\u52A0\u5165 NocoDB \u793E\u7FA4",
    joinReddit: "\u52A0\u5165 /r/NocoDB",
    followNocodb: "\u8FFD\u8E64 NocoDB"
  },
  docReference: "\u6587\u4EF6\u53C3\u8003\u6587\u737B",
  selectUserRole: "\u9078\u64C7\u4F7F\u7528\u8005\u89D2\u8272",
  childTable: "\u5B50\u8868\u683C",
  childColumn: "\u5B50\u6B04",
  onUpdate: "\u66F4\u65B0",
  onDelete: "\u5728\u522A\u9664"
};
const activity = {
  createProject: "\u5EFA\u7ACB\u5C08\u6848",
  importProject: "\u532F\u5165\u5C08\u6848",
  searchProject: "\u641C\u5C0B\u5C08\u6848",
  editProject: "\u7DE8\u8F2F\u5C08\u6848",
  stopProject: "\u505C\u6B62\u5C08\u6848",
  startProject: "\u555F\u52D5\u5C08\u6848",
  restartProject: "\u91CD\u555F\u5C08\u6848",
  deleteProject: "\u522A\u9664\u5C08\u6848",
  refreshProject: "\u91CD\u65B0\u6574\u7406\u5C08\u6848",
  saveProject: "\u5132\u5B58\u5C08\u6848",
  createProjectExtended: {
    extDB: "\u9023\u7DDA\u81F3\u5916\u90E8\u8CC7\u6599\u5EAB\u4F86\u5EFA\u7ACB",
    excel: "\u5F9E Excel \u5EFA\u7ACB\u5C08\u6848",
    template: "\u5F9E\u6A21\u677F\u5EFA\u7ACB\u5C08\u6848"
  },
  OkSaveProject: "\u78BA\u8A8D\u4E26\u5132\u5B58\u5C08\u6848",
  upgrade: {
    available: "\u5347\u7D1A\u53EF\u7528",
    releaseNote: "\u767C\u884C\u8AAA\u660E",
    howTo: "\u5982\u4F55\u5347\u7D1A\uFF1F"
  },
  translate: "\u5E6B\u52A9\u7FFB\u8B6F",
  account: {
    authToken: "\u8907\u88FD\u9A57\u8B49\u6B0A\u6756",
    swagger: "Swagger Api \u8AAA\u660E\u6587\u4EF6",
    projInfo: "\u8907\u88FD\u5C08\u6848\u8CC7\u8A0A",
    themes: "\u4E3B\u984C"
  },
  sort: "\u7A2E\u985E",
  addSort: "\u6DFB\u52A0\u6392\u5E8F\u9078\u9805",
  filter: "\u7BE9\u9078",
  addFilter: "\u6DFB\u52A0\u904E\u6FFE\u5668",
  share: "\u5206\u4EAB",
  shareBase: {
    disable: "\u7981\u7528\u5171\u4EAB\u57FA\u790E",
    enable: "\u4EFB\u4F55\u6709\u9023\u7D50\u7684\u4EBA",
    link: "\u5171\u4EAB\u57FA\u672C\u93C8\u63A5"
  },
  invite: "\u9080\u8ACB",
  inviteMore: "\u9080\u8ACB\u66F4\u591A",
  inviteTeam: "\u9080\u8ACB\u5718\u968A",
  inviteToken: "\u9080\u8ACB\u6B0A\u6756",
  newUser: "\u65B0\u4F7F\u7528\u8005",
  editUser: "\u7DE8\u8F2F\u4F7F\u7528\u8005",
  deleteUser: "\u5F9E\u5C08\u6848\u4E2D\u522A\u9664\u4F7F\u7528\u8005",
  resendInvite: "\u91CD\u65B0\u767C\u9001\u9080\u8ACB\u96FB\u5B50\u90F5\u4EF6",
  copyInviteURL: "\u8907\u88FD\u9080\u8ACB\u9023\u7D50",
  newRole: "\u65B0\u89D2\u8272",
  reloadRoles: "\u91CD\u65B0\u8F09\u5165\u89D2\u8272",
  nextPage: "\u4E0B\u4E00\u9801",
  prevPage: "\u4E0A\u4E00\u9801",
  nextRecord: "\u4E0B\u4E00\u6B65\u8A18\u9304",
  previousRecord: "\u4E4B\u524D\u7684\u7D00\u9304",
  copyApiURL: "\u8907\u88FD API \u7DB2\u5740",
  createTable: "\u8868\u5275\u9020",
  refreshTable: "\u8868\u5237\u65B0",
  renameTable: "\u8868\u91CD\u547D\u540D",
  deleteTable: "\u8868\u522A\u9664",
  addField: "\u5C07\u65B0\u5B57\u6BB5\u6DFB\u52A0\u5230\u6B64\u8868",
  setPrimary: "\u8A2D\u7F6E\u70BA\u4E3B\u8981\u503C",
  addRow: "\u65B0\u589E\u884C",
  saveRow: "\u5132\u5B58\u884C",
  insertRow: "\u63D2\u5165\u65B0\u884C",
  deleteRow: "\u522A\u9664\u884C",
  deleteSelectedRow: "\u522A\u9664\u6240\u9078\u884C",
  importExcel: "\u532F\u5165 Excel",
  importCSV: "\u532F\u5165 CSV",
  downloadCSV: "\u4E0B\u8F09\u70BA CSV",
  downloadExcel: "\u4E0B\u8F09\u70BA XLSX",
  uploadCSV: "\u4E0A\u50B3 CSV",
  "import": "\u532F\u5165",
  importMetadata: "\u532F\u5165\u4E2D\u7E7C\u8CC7\u6599",
  exportMetadata: "\u532F\u51FA\u4E2D\u7E7C\u8CC7\u6599",
  clearMetadata: "\u6E05\u9664\u4E2D\u7E7C\u8CC7\u6599",
  exportToFile: "\u532F\u51FA\u70BA\u6A94\u6848",
  changePwd: "\u66F4\u6539\u5BC6\u78BC",
  createView: "\u5EFA\u7ACB\u6AA2\u8996\u8868",
  shareView: "\u5206\u4EAB\u6AA2\u8996\u8868",
  listSharedView: "\u5171\u4EAB\u8996\u5716\u5217\u8868",
  ListView: "\u6AA2\u8996\u8868\u6E05\u55AE",
  copyView: "\u8907\u88FD\u6AA2\u8996\u8868",
  renameView: "\u91CD\u65B0\u547D\u540D\u6AA2\u8996\u8868",
  deleteView: "\u522A\u9664\u6AA2\u8996\u8868",
  createGrid: "\u5275\u5EFA\u7DB2\u683C\u8996\u5716",
  createGallery: "\u5275\u5EFA\u756B\u5ECA\u8996\u5716",
  createCalendar: "\u5275\u5EFA\u65E5\u66C6\u8996\u5716",
  createKanban: "\u5275\u5EFA\u5C0B\u547C\u8996\u5716",
  createForm: "\u5275\u5EFA\u8868\u55AE\u8996\u5716",
  showSystemFields: "\u986F\u793A\u7CFB\u7D71\u5B57\u6BB5",
  copyUrl: "\u8907\u88FD\u7DB2\u5740",
  openTab: "\u958B\u555F\u65B0\u5206\u9801",
  iFrame: "\u8907\u88FD\u5D4C\u5165\u5F0F HTML \u7A0B\u5F0F\u78BC",
  addWebhook: "\u65B0\u589E webhook",
  newToken: "\u65B0\u589E\u6B0A\u6756",
  exportZip: "\u532F\u51FA ZIP",
  importZip: "\u532F\u5165 ZIP",
  metaSync: "\u7ACB\u5373\u540C\u6B65",
  settings: "\u8A2D\u5B9A",
  previewAs: "\u9810\u89BD\u65B9\u5F0F",
  resetReview: "\u91CD\u8A2D\u9810\u89BD",
  testDbConn: "\u6E2C\u8A66\u8CC7\u6599\u5EAB\u9023\u7DDA",
  removeDbFromEnv: "\u5F9E\u74B0\u5883\u79FB\u9664\u8CC7\u6599\u5EAB",
  editConnJson: "\u7DE8\u8F2F\u9023\u7DDA JSON",
  sponsorUs: "\u8D0A\u52A9\u6211\u5011",
  sendEmail: "\u50B3\u9001\u96FB\u5B50\u90F5\u4EF6"
};
const tooltip = {
  saveChanges: "\u5132\u5B58\u66F4\u52D5",
  xcDB: "\u5EFA\u7ACB\u65B0\u5C08\u6848",
  extDB: "\u652F\u63F4 MySQL\u3001PostgreSQL\u3001SQL Server \u548C SQLite",
  apiRest: "\u53EF\u900F\u904E REST API \u5B58\u53D6",
  apiGQL: "\u53EF\u900F\u904E GraphQL API \u5B58\u53D6",
  theme: {
    dark: "\u5B83\u78BA\u5BE6\u6709\u9ED1\u8272\uFF08^\u21E7b\uFF09",
    light: "\u5B83\u662F\u9ED1\u8272\u55CE\uFF1F\uFF08^\u21E7b\uFF09"
  },
  addTable: "\u6DFB\u52A0\u65B0\u8868",
  inviteMore: "\u9080\u8ACB\u66F4\u591A\u7528\u6236",
  toggleNavDraw: "\u5207\u63DB\u5C0E\u822A\u62BD\u5C5C",
  reloadApiToken: "\u91CD\u65B0\u8F09\u5165 API \u6B0A\u6756",
  generateNewApiToken: "\u7522\u751F\u65B0 API \u6B0A\u6756",
  addRole: "\u6DFB\u52A0\u65B0\u89D2\u8272",
  reloadList: "\u91CD\u65B0\u52A0\u8F09\u5217\u8868",
  metaSync: "\u540C\u6B65\u4E2D\u7E7C\u8CC7\u6599",
  sqlMigration: "\u91CD\u65B0\u52A0\u8F09\u9077\u79FB",
  updateRestart: "\u66F4\u65B0\u4E26\u91CD\u65B0\u555F\u52D5",
  cancelReturn: "\u53D6\u6D88\u4E26\u8FD4\u56DE",
  exportMetadata: "\u5C07\u6240\u6709\u4E2D\u7E7C\u8CC7\u6599\u5F9E\u4E2D\u7E7C\u8CC7\u6599\u8868\u532F\u51FA\u81F3\u4E2D\u7E7C\u76EE\u9304\u3002",
  importMetadata: "\u5C07\u6240\u6709\u4E2D\u7E7C\u8CC7\u6599\u5F9E\u4E2D\u7E7C\u76EE\u9304\u532F\u5165\u81F3\u4E2D\u7E7C\u8CC7\u6599\u8868\u3002",
  clearMetadata: "\u6E05\u9664\u4E2D\u7E7C\u8CC7\u6599\u8868\u4E2D\u7684\u6240\u6709\u4E2D\u7E7C\u8CC7\u6599\u3002",
  clientKey: "\u9078\u64C7 .key \u6A94\u6848",
  clientCert: "\u9078\u64C7 .cert \u6A94\u6848",
  clientCA: "\u9078\u64C7 CA \u6A94\u6848"
};
const placeholder = {
  projName: "\u8F38\u5165\u5C08\u6848\u540D\u7A31",
  password: {
    enter: "\u8F38\u5165\u5BC6\u78BC",
    current: "\u7576\u524D\u5BC6\u78BC",
    "new": "\u65B0\u5BC6\u78BC",
    save: "\u5132\u5B58\u5BC6\u78BC",
    confirm: "\u78BA\u8A8D\u65B0\u5BC6\u78BC"
  },
  searchProjectTree: "\u641C\u7D22\u8868",
  searchFields: "\u641C\u7D22\u5B57\u6BB5",
  searchColumn: "\u641C\u7D22{search}\u5217",
  searchApps: "\u641C\u7D22\u61C9\u7528\u7A0B\u5E8F",
  searchModels: "\u641C\u7D22\u6A21\u578B",
  noItemsFound: "\u672A\u627E\u5230\u4EFB\u4F55\u9805\u76EE",
  defaultValue: "\u9810\u8A2D\u503C",
  filterByEmail: "\u901A\u904E\u96FB\u5B50\u90F5\u4EF6\u904E\u6FFE"
};
const msg = {
  info: {
    footerInfo: "\u6BCF\u9801\u884C\u99DB",
    upload: "\u9078\u64C7\u6A94\u6848\u4EE5\u4E0A\u50B3",
    upload_sub: "\u6216\u62D6\u653E\u6A94\u6848",
    excelSupport: "\u652F\u6301\uFF1A.xls\uFF0C.xlsx\uFF0C.xlsm\uFF0C.ods\uFF0C.ots",
    excelURL: "\u8F38\u5165 Excel \u6A94\u6848 URL",
    csvURL: "\u8F38\u5165 CSV \u6A94\u6848 URL",
    footMsg: "\u8981\u89E3\u6790\u70BA\u63A8\u65B7\u6578\u64DA\u985E\u578B\u7684\u884C\u6578",
    excelImport: "\u677F\u6750\u53EF\u7528\u65BC\u9032\u53E3",
    exportMetadata: "\u60A8\u60F3\u5F9E\u4E2D\u7E7C\u8868\u683C\u4E2D\u532F\u51FA\u4E2D\u7E7C\u8CC7\u6599\u55CE\uFF1F",
    importMetadata: "\u60A8\u60F3\u5F9E\u4E2D\u7E7C\u8868\u683C\u4E2D\u532F\u5165\u4E2D\u7E7C\u8CC7\u6599\u55CE\uFF1F",
    clearMetadata: "\u4F60\u60F3\u6E05\u9664\u4E2D\u7E7C\u8868\u683C\u4E2D\u7684\u4E2D\u7E7C\u8CC7\u6599\u55CE\uFF1F",
    projectEmptyMessage: "\u5F9E\u5EFA\u7ACB\u65B0\u5C08\u6848\u958B\u59CB",
    stopProject: "\u4F60\u60F3\u505C\u6B62\u9019\u500B\u5C08\u6848\u55CE\uFF1F",
    startProject: "\u4F60\u60F3\u555F\u52D5\u9019\u500B\u5C08\u6848\u55CE\uFF1F",
    restartProject: "\u4F60\u60F3\u91CD\u65B0\u555F\u52D5\u5C08\u6848\u55CE\uFF1F",
    deleteProject: "\u4F60\u60F3\u522A\u9664\u9019\u500B\u5C08\u6848\u55CE\uFF1F",
    shareBasePrivate: "\u7522\u751F\u516C\u958B\u53EF\u4EAB\u7684 Readonly Base",
    shareBasePublic: "\u7DB2\u8DEF\u4E0A\u7684\u4EFB\u4F55\u4EBA\u90FD\u53EF\u4EE5\u67E5\u770B",
    userInviteNoSMTP: "\u770B\u8D77\u4F86\u4F60\u9084\u6C92\u6709\u914D\u7F6E\u90F5\u4EF6\uFF01\u8ACB\u8907\u5236\u4E0A\u9762\u7684\u9080\u8ACB\u93C8\u63A5\u4E26\u5C07\u5176\u767C\u9001\u7D66",
    dragDropHide: "\u5728\u6B64\u8655\u62D6\u653E\u5B57\u6BB5\u4EE5\u96B1\u85CF",
    formInput: "\u8F38\u5165\u8868\u55AE\u8F38\u5165\u6A19\u7C64",
    formHelpText: "\u6DFB\u52A0\u4E00\u4E9B\u5E6B\u52A9\u6587\u672C",
    onlyCreator: "\u50C5\u5EFA\u7ACB\u8005\u53EF\u898B",
    formDesc: "\u6DFB\u52A0\u8868\u55AE\u63CF\u8FF0",
    beforeEnablePwd: "\u4F7F\u7528\u5BC6\u78BC\u9650\u5236\u5B58\u53D6\u6B0A\u9650",
    afterEnablePwd: "\u5B58\u53D6\u53D7\u5BC6\u78BC\u9650\u5236",
    privateLink: "\u6B64\u6AA2\u8996\u8868\u901A\u904E\u79C1\u4EBA\u9023\u7D50\u5171\u4EAB",
    privateLinkAdditionalInfo: "\u5177\u6709\u79C1\u6709\u9023\u7D50\u7684\u4EBA\u53EA\u80FD\u770B\u5230\u6B64\u6AA2\u8996\u8868\u4E2D\u53EF\u898B\u7684\u5132\u5B58\u683C",
    afterFormSubmitted: "\u8868\u683C\u63D0\u4EA4\u5F8C",
    apiOptions: "\u5B58\u53D6\u5C08\u6848\u65B9\u5F0F",
    submitAnotherForm: "\u986F\u793A\u201C\u63D0\u4EA4\u53E6\u4E00\u500B\u8868\u683C\u201D\u6309\u9215",
    showBlankForm: "5 \u79D2\u5F8C\u986F\u793A\u7A7A\u767D\u8868\u683C",
    emailForm: "\u767C\u96FB\u5B50\u90F5\u4EF6\u7D66\u6211",
    showSysFields: "\u986F\u793A\u7CFB\u7D71\u5B57\u6BB5",
    filterAutoApply: "\u81EA\u52D5\u7533\u8ACB",
    showMessage: "\u986F\u793A\u6B64\u6D88\u606F",
    viewNotShared: "\u7576\u524D\u8996\u5716\u4E0D\u5171\u4EAB\uFF01",
    showAllViews: "\u986F\u793A\u6B64\u8868\u7684\u6240\u6709\u5171\u4EAB\u8996\u5716",
    collabView: "\u5177\u6709\u7DE8\u8F2F\u6B0A\u9650\u6216\u66F4\u9AD8\u7684\u5408\u4F5C\u8005\u53EF\u4EE5\u66F4\u6539\u8996\u5716\u914D\u7F6E\u3002",
    lockedView: "\u6C92\u6709\u4EBA\u53EF\u4EE5\u7DE8\u8F2F\u8996\u5716\u914D\u7F6E\uFF0C\u76F4\u5230\u5B83\u88AB\u89E3\u9396\u3002",
    personalView: "\u53EA\u6709\u60A8\u53EF\u4EE5\u7DE8\u8F2F\u8996\u5716\u914D\u7F6E\u3002\u9ED8\u8A8D\u60C5\u6CC1\u4E0B\uFF0C\u5176\u4ED6\u5408\u4F5C\u8005\u7684\u500B\u4EBA\u8996\u5716\u96B1\u85CF\u3002",
    ownerDesc: "\u53EF\u4EE5\u6DFB\u52A0/\u522A\u9664\u5275\u5EFA\u8005\u3002\u548C\u5B8C\u6574\u7DE8\u8F2F\u6578\u64DA\u5EAB\u7D50\u69CB\u548C\u5B57\u6BB5\u3002",
    creatorDesc: "\u53EF\u4EE5\u5B8C\u5168\u7DE8\u8F2F\u6578\u64DA\u5EAB\u7D50\u69CB\u548C\u503C\u3002",
    editorDesc: "\u53EF\u4EE5\u7DE8\u8F2F\u8A18\u9304\u4F46\u7121\u6CD5\u66F4\u6539\u6578\u64DA\u5EAB/\u5B57\u6BB5\u7684\u7D50\u69CB\u3002",
    commenterDesc: "\u53EF\u4EE5\u67E5\u770B\u548C\u8A55\u8AD6\u8A18\u9304\uFF0C\u4F46\u7121\u6CD5\u7DE8\u8F2F\u4EFB\u4F55\u5167\u5BB9",
    viewerDesc: "\u53EF\u4EE5\u67E5\u770B\u8A18\u9304\u4F46\u7121\u6CD5\u7DE8\u8F2F\u4EFB\u4F55\u5167\u5BB9",
    addUser: "\u65B0\u589E\u4F7F\u7528\u8005",
    staticRoleInfo: "\u7121\u6CD5\u7DE8\u8F2F\u7CFB\u7D71\u5B9A\u7FA9\u7684\u89D2\u8272",
    exportZip: "\u5C07\u5C08\u6848\u4E2D\u7E7C\u8CC7\u6599\u532F\u51FA\u70BA ZIP \u6A94\u6848\u4E26\u4E0B\u8F09\u3002",
    importZip: "\u532F\u5165\u5C08\u6848\u4E2D\u7E7C\u8CC7\u6599 ZIP \u6A94\u6848\u4E26\u91CD\u65B0\u555F\u52D5\u3002",
    importText: "\u900F\u904E\u4E0A\u50B3\u4E2D\u7E7C\u8CC7\u6599 ZIP \u6A94\u6848\u4F86\u532F\u5165 NocoDB \u5C08\u6848",
    metaNoChange: "\u6C92\u6709\u78BA\u5B9A\u66F4\u6539",
    sqlMigration: "\u5C07\u81EA\u52D5\u5275\u5EFA\u67B6\u69CB\u9077\u79FB\u3002\u5275\u5EFA\u4E00\u500B\u8868\u4E26\u5237\u65B0\u6B64\u9801\u9762\u3002",
    dbConnectionStatus: "\u74B0\u5883\u9A57\u8B49",
    dbConnected: "\u9023\u7DDA\u6210\u529F",
    notifications: {
      no_new: "\u6C92\u6709\u65B0\u901A\u77E5",
      clear: "\u6E05\u9664"
    },
    sponsor: {
      header: "\u4F60\u53EF\u4EE5\u5E6B\u52A9\u6211\u5011\uFF01",
      message: "\u6211\u5011\u662F\u4E00\u652F\u5C0F\u578B\u5718\u968A\uFF0C\u5168\u8077\u5DE5\u4F5C\uFF0C\u4F7FNocodb\u958B\u653E\u4F86\u6E90\u3002\u6211\u5011\u76F8\u4FE1\u4E00\u500B\u50CFNocodb\u9019\u6A23\u7684\u5DE5\u5177\u61C9\u8A72\u5728\u4E92\u806F\u7DB2\u4E0A\u7684\u6BCF\u500B\u554F\u984C\u6C42\u89E3\u5668\u4E0A\u81EA\u7531\u63D0\u4F9B\u3002"
    },
    loginMsg: "\u767B\u5165 NocoDB",
    passwordRecovery: {
      message_1: "\u8ACB\u586B\u5165\u60A8\u8A3B\u518A\u6642\u4F7F\u7528\u7684\u96FB\u5B50\u4FE1\u7BB1\u5730\u5740\u3002",
      message_2: "\u6211\u5011\u5C07\u50B3\u7D66\u60A8\u4E00\u5C01\u96FB\u5B50\u90F5\u4EF6\uFF0C\u5176\u4E2D\u5305\u542B\u91CD\u8A2D\u5BC6\u78BC\u7684\u9023\u7D50\u3002",
      success: "\u8ACB\u78BA\u8A8D\u60A8\u7684\u96FB\u5B50\u90F5\u4EF6\u4EE5\u91CD\u8A2D\u5BC6\u78BC"
    },
    signUp: {
      superAdmin: "\u60A8\u5C07\u662F\u300C\u8D85\u7D1A\u7BA1\u7406\u54E1\u300D",
      alreadyHaveAccount: "\u5DF2\u7D93\u6709\u5E33\u865F\u4E86\uFF1F",
      workEmail: "\u8F38\u5165\u60A8\u7684\u5DE5\u4F5C\u96FB\u5B50\u4FE1\u7BB1\u5730\u5740",
      enterPassword: "\u8F38\u5165\u60A8\u7684\u5BC6\u78BC",
      forgotPassword: "\u5FD8\u8A18\u5BC6\u78BC\uFF1F",
      dontHaveAccount: "\u6C92\u6709\u5E33\u865F\uFF1F"
    },
    addView: {
      grid: "\u52A0\u5165\u7DB2\u683C\u6AA2\u8996\u8868",
      gallery: "\u52A0\u5165\u5716\u5EAB\u6AA2\u8996\u8868",
      form: "\u52A0\u5165\u8868\u55AE\u6AA2\u8996\u8868",
      kanban: "\u52A0\u5165\u770B\u677F\u6AA2\u8996\u8868",
      calendar: "\u52A0\u5165\u65E5\u66C6\u6AA2\u8996\u8868"
    },
    tablesMetadataInSync: "\u8868\u5143\u6578\u64DA\u540C\u6B65",
    addMultipleUsers: "\u60A8\u53EF\u4EE5\u6DFB\u52A0\u591A\u500B\u9017\u865F\uFF08\uFF0C\uFF09\u5206\u9694\u7684\u96FB\u5B50\u90F5\u4EF6",
    enterTableName: "\u8F38\u5165\u8868\u540D",
    addDefaultColumns: "\u6DFB\u52A0\u9ED8\u8A8D\u5217",
    tableNameInDb: "\u6578\u64DA\u5EAB\u4E2D\u4FDD\u5B58\u7684\u8868\u540D"
  },
  error: {
    searchProject: "\u60A8\u7684\u641C\u5C0B {search} \u627E\u4E0D\u5230\u7D50\u679C",
    invalidChar: "\u8CC7\u6599\u593E\u8DEF\u5F91\u6709\u7121\u6548\u5B57\u5143\u3002",
    invalidDbCredentials: "\u8CC7\u6599\u5EAB\u6191\u8B49\u7121\u6548\u3002",
    unableToConnectToDb: "\u7121\u6CD5\u9023\u7DDA\u81F3\u8CC7\u6599\u5EAB\u3002\u8ACB\u6AA2\u67E5\u60A8\u7684\u8CC7\u6599\u5EAB\u662F\u5426\u5DF2\u7D93\u4E0A\u7DDA\u3002",
    userDoesntHaveSufficientPermission: "\u4F7F\u7528\u8005\u4E0D\u5B58\u5728\uFF0C\u6216\u8005\u662F\u7121\u6B0A\u5EFA\u7ACB\u7D50\u69CB\u3002",
    dbConnectionStatus: "\u8CC7\u6599\u5EAB\u53C3\u6578\u7121\u6548",
    dbConnectionFailed: "\u9023\u7DDA\u5931\u6557\uFF1A",
    signUpRules: {
      emailReqd: "\u96FB\u5B50\u4FE1\u7BB1\u5730\u5740\u70BA\u5FC5\u586B",
      emailInvalid: "\u96FB\u5B50\u4FE1\u7BB1\u5730\u5740\u683C\u5F0F\u932F\u8AA4",
      passwdRequired: "\u5BC6\u78BC\u70BA\u5FC5\u586B",
      passwdLength: "\u60A8\u7684\u5BC6\u78BC\u61C9\u81F3\u5C11\u6709 8 \u500B\u5B57\u5143"
    }
  },
  toast: {
    exportMetadata: "\u5C08\u6848\u4E2D\u7E7C\u8CC7\u6599\u5DF2\u6210\u529F\u532F\u51FA",
    importMetadata: "\u5C08\u6848\u4E2D\u7E7C\u8CC7\u6599\u5DF2\u6210\u529F\u532F\u5165",
    clearMetadata: "\u5C08\u6848\u4E2D\u7E7C\u8CC7\u6599\u5DF2\u6210\u529F\u6E05\u9664",
    stopProject: "\u5C08\u6848\u6210\u529F\u505C\u6B62",
    startProject: "\u5C08\u6848\u6210\u529F\u555F\u52D5",
    restartProject: "\u5C08\u6848\u6210\u529F\u91CD\u65B0\u555F\u52D5",
    deleteProject: "\u5C08\u6848\u5DF2\u6210\u529F\u522A\u9664",
    authToken: "\u9A57\u8B49\u6B0A\u6756\u5DF2\u8907\u88FD\u5230\u526A\u8CBC\u7C3F",
    projInfo: "\u5DF2\u5C07\u5C08\u6848\u8CC7\u8A0A\u8907\u88FD\u5230\u526A\u8CBC\u7C3F",
    inviteUrlCopy: "\u5DF2\u5C07\u9080\u8ACB\u9023\u7D50\u8907\u88FD\u5230\u526A\u8CBC\u7C3F",
    createView: "\u6210\u529F\u5EFA\u7ACB\u6AA2\u8996\u8868",
    formEmailSMTP: "\u8ACB\u555F\u7528 App Store \u4E2D\u7684 SMTP \u5916\u639B\u7A0B\u5F0F\u4EE5\u555F\u7528\u96FB\u5B50\u90F5\u4EF6\u901A\u77E5",
    collabView: "\u6210\u529F\u8F49\u63DB\u70BA\u5354\u4F5C\u8996\u5716",
    lockedView: "\u6210\u529F\u8F49\u63DB\u70BA\u9396\u5B9A\u8996\u5716",
    futureRelease: "\u5373\u5C07\u63A8\u51FA\uFF01"
  }
};
var zh_TW = {
  general,
  objects,
  datatype,
  filterOperation,
  title,
  labels,
  activity,
  tooltip,
  placeholder,
  msg
};
export { activity, datatype, zh_TW as default, filterOperation, general, labels, msg, objects, placeholder, title, tooltip };