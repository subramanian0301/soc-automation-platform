export function normalizeKey(key: string): string {
  if (!key) return '';
  return key.toLowerCase().replace(/[^a-z0-9]/g, '');
}

export const ALIAS_MAPS = {
  metadata: {
    hostname: ['hostname', 'host', 'host_name', 'system_host', 'systemhost', 'computername', 'computer_name', 'devicename', 'device_name', 'systemname', 'system_name', 'endpointname', 'endpoint_name', 'nodename', 'node_name', 'node', 'nodehost', 'node_host'],
    username: ['username', 'user', 'user_name', 'useraccount', 'user_account', 'account', 'loggeduser', 'logged_user', 'domainuser', 'domain_user', 'operator'],
    operatingSystem: ['operatingsystem', 'operating_system', 'os', 'osname', 'os_name', 'osversion', 'os_version', 'platform'],
    analysisTime: ['analysistime', 'analysis_time', 'timestamp', 'createdat', 'created_at', 'scantime', 'scan_time', 'date', 'eventtime', 'event_time'],
  },
  risk: {
    riskScore: ['riskscore', 'risk_score', 'score', 'risk_value', 'riskvalue', 'overall_score', 'overallscore'],
    threatLevel: ['threatlevel', 'threat_level', 'level', 'severity', 'severity_level', 'risk_level', 'risklevel'],
    recommendation: ['recommendation', 'recommendations', 'remediation', 'action', 'suggested_action', 'resolution'],
  },
  hashes: {
    md5: ['md5', 'md5_hash', 'md5hash', 'file_md5'],
    sha1: ['sha1', 'sha1_hash', 'sha1hash', 'file_sha1'],
    sha256: ['sha256', 'sha256_hash', 'sha256hash', 'file_sha256'],
    ssdeep: ['ssdeep', 'ssdeep_hash', 'ssdeephash'],
  },
  fileProperties: {
    entropy: ['entropy', 'file_entropy'],
    digitalSignature: ['digitalsignature', 'digital_signature', 'signature', 'signature_status', 'signed'],
    isPacked: ['ispacked', 'is_packed', 'packed', 'packing'],
    packer: ['packer', 'packer_name', 'packer_info', 'packer_type'],
    imports: ['imports', 'imported_functions', 'dll_imports', 'imported_dlls'],
    suspiciousApis: ['suspiciousapis', 'suspicious_apis', 'suspicious_calls', 'suspicious_functions'],
  },
  yara: {
    ruleName: ['rulename', 'rule_name', 'rule', 'yara_rule', 'yararule', 'rule_identifier', 'matchedrule', 'matched_rule'],
    namespace: ['namespace', 'rule_namespace'],
    tags: ['tags', 'rule_tags'],
    meta: ['meta', 'rule_meta', 'metadata'],
    description: ['description', 'desc', 'summary'],
  },
  virusTotal: {
    positives: ['positives', 'positive_detections', 'malicious_count', 'detections_count', 'positives_count', 'score', 'detectionratio', 'detection_ratio'],
    total: ['total', 'total_scans', 'engines_count', 'scanners_count', 'total_engines'],
    permalink: ['permalink', 'url', 'vt_url', 'link'],
    scanDate: ['scandate', 'scan_date', 'date'],
    detections: ['detections', 'engine_results', 'scans'],
  },
  iocs: {
    type: ['ioctype', 'ioc_type', 'type', 'indicator_type', 'kind'],
    value: ['iocvalue', 'ioc_value', 'value', 'indicator', 'indicator_value', 'observable', 'remoteip', 'remote_ip', 'commandcontroldomain', 'command_control_domain', 'malwaredistributiondomain', 'malware_distribution_domain', 'url', 'emailioc', 'email_ioc'],
    category: ['category', 'ioc_category', 'threat_category'],
    confidence: ['confidence', 'confidence_score', 'reliability'],
    description: ['description', 'desc', 'details', 'comment'],
  },
  mitre: {
    tactic: ['tactic', 'mitre_tactic', 'tactic_name', 'phase'],
    techniqueId: ['techniqueid', 'technique_id', 'mitreid', 'mitre_id', 'attack_id', 'id'],
    name: ['techniquename', 'technique_name', 'name', 'technique', 'title'],
    description: ['description', 'desc', 'details', 'summary'],
  },
  behavior: {
    eventType: ['eventtype', 'event_type', 'type', 'category', 'action_type'],
    action: ['behavioraction', 'behavior_action', 'action', 'activity', 'operation'],
    target: ['target', 'target_path', 'object', 'destination', 'process', 'file', 'registry_key', 'processespawned', 'processes_spawned', 'persistence', 'droppedfile', 'dropped_file', 'scheduledtask', 'scheduled_task', 'createdprocess', 'created_process', 'processcreated', 'process_created', 'registrymodified', 'registry_modified', 'droppedfiles', 'dropped_files'],
    details: ['details', 'description', 'args', 'command_line', 'parameters'],
    timestamp: ['timestamp', 'time', 'date', 'event_time'],
  },
  sandbox: {
    sandboxName: ['sandboxname', 'sandbox_name', 'sandbox', 'engine', 'system', 'environment', 'env', 'run_id', 'runid', 'os', 'system_name'],
    verdict: ['sandboxverdict', 'sandbox_verdict', 'verdict', 'result', 'status'],
    score: ['sandboxscore', 'sandbox_score', 'score', 'threat_score'],
    details: ['details', 'report', 'output', 'findings'],
    processesCreated: ['processescreated', 'processes_created', 'createdprocesses', 'created_processes'],
    filesCreated: ['filescreated', 'files_created', 'createdfiles', 'created_files'],
    registryKeys: ['registrykeys', 'registry_keys', 'registrykeysmodified', 'registry_keys_modified'],
    networkRequests: ['networkrequests', 'network_requests', 'networkconnections', 'network_connections'],
  },
  siem: {
    eventId: ['eventid', 'event_id', 'id', 'log_id', 'record_id', 'event_code', 'eventcode', 'signature_id', 'sig_id', 'code', 'task_category'],
    sourceIp: ['sourceip', 'source_ip', 'srcip', 'src_ip', 'src', 'source', 'client_ip', 'clientip', 'client', 'remote_ip', 'remoteip', 'src_host', 'srchost', 'source_address', 'src_addr', 'client_address', 'c_ip', 'cip', 'ip_src'],
    destIp: ['destip', 'dest_ip', 'destinationip', 'destination_ip', 'dstip', 'dst_ip', 'dst', 'destination', 'server_ip', 'serverip', 'server', 'target_ip', 'targetip', 'dst_host', 'dest_address', 'dst_addr', 'server_address', 's_ip', 'sip', 'ip_dst'],
    sourcePort: ['sourceport', 'source_port', 'srcport', 'src_port', 'sport', 'spt', 'c_port', 'cport'],
    destPort: ['destport', 'dest_port', 'destinationport', 'destination_port', 'dstport', 'dst_port', 'dport', 'dpt', 's_port', 'sport'],
    protocol: ['protocol', 'proto', 'transport', 'network_protocol'],
    action: ['action', 'disposition', 'decision', 'status', 'event_action', 'act', 'method', 'verdict', 'outcome', 'result'],
    severity: ['severity', 'level', 'priority', 'log_level', 'loglevel', 'threat_level', 'crit', 'sev', 'importance'],
    rawEvent: ['rawevent', 'raw_event', 'message', 'msg', 'log', 'raw_log', 'rawlog', 'event', 'details', 'raw', 'line', 'text', 'description', 'desc', 'summary', 'content'],
    timestamp: ['timestamp', 'time', 'date', 'event_time', 'eventtime', 'log_time', 'logtime', '@timestamp', 'datetime', 'devtime', 'rt', 'event_timestamp'],
  },
  incidents: {
    title: ['incidenttitle', 'incident_title', 'title', 'name', 'subject', 'incidentid', 'incident_id'],
    severity: ['severity', 'threat_level', 'priority'],
    status: ['status', 'incident_status', 'state'],
    reason: ['reason', 'trigger', 'explanation', 'cause'],
    assignedTo: ['assignedto', 'assigned_to', 'assignee', 'owner'],
  },
  soar: {
    actionName: ['actionname', 'action_name', 'playbook', 'playbook_name', 'action', 'command', 'executed', 'completed'],
    description: ['description', 'desc', 'summary'],
    actionType: ['actiontype', 'action_type', 'type'],
    target: ['target', 'target_asset', 'recipient', 'destination'],
    status: ['status', 'execution_status', 'state'],
    triggeredBy: ['triggeredby', 'triggered_by', 'initiator', 'source'],
    source: ['source', 'module'],
    result: ['result', 'output', 'outcome'],
    executionLog: ['executionlog', 'execution_log', 'log', 'details'],
    executedAt: ['executedat', 'executed_at', 'start_time'],
    completedAt: ['completedat', 'completed_at', 'end_time'],
  },
  assets: {
    assetName: ['assetname', 'asset_name', 'asset', 'name', 'device', 'host'],
    hostname: ['hostname', 'host', 'computer_name'],
    ipAddress: ['ipaddress', 'ip_address', 'ip'],
    macAddress: ['macaddress', 'mac_address', 'mac'],
    assetType: ['assettype', 'asset_type', 'type', 'kind'],
    criticality: ['criticality', 'importance', 'business_value'],
    operatingSystem: ['operatingsystem', 'operating_system', 'os'],
    owner: ['owner', 'user', 'custodian'],
    status: ['status', 'asset_status', 'state'],
    source: ['source', 'origin'],
    description: ['description', 'details'],
    evidence: ['evidence', 'proof', 'notes'],
  },
  endpoints: {
    hostname: ['endpointname', 'endpoint_name', 'hostname', 'host', 'device_name', 'computer_name'],
    ipAddress: ['ipaddress', 'ip_address', 'ip'],
    osVersion: ['osversion', 'os_version', 'os', 'operating_system'],
    operatingSystem: ['operatingsystem', 'operating_system', 'os'],
    user: ['user', 'username', 'logged_user'],
    agentStatus: ['agentstatus', 'agent_status', 'status', 'health'],
    status: ['status', 'endpoint_status', 'state'],
    endpointType: ['endpointtype', 'endpoint_type', 'type'],
    source: ['source', 'origin'],
    evidence: ['evidence', 'proof', 'notes'],
    lastSeen: ['lastseen', 'last_seen', 'last_checkin', 'timestamp'],
  },
  vulnerabilities: {
    cveId: ['cveid', 'cve_id', 'cve', 'vulnerabilityid', 'vulnerability_id', 'vulnid', 'vuln_id', 'cve_number'],
    title: ['vulnerabilitytitle', 'vulnerability_title', 'vulnerabilityname', 'vulnerability_name', 'vuln_name', 'title', 'name'],
    cvssScore: ['cvssscore', 'cvss_score', 'cvss', 'score', 'severity_score'],
    severity: ['threatseverity', 'threat_severity', 'severity', 'threatlevel', 'threat_level'],
    description: ['description', 'desc', 'summary', 'details'],
    affectedAsset: ['affectedasset', 'affected_asset', 'asset', 'target', 'host'],
    packageName: ['packagename', 'package_name', 'package', 'component', 'software'],
    installedVersion: ['installedversion', 'installed_version', 'currentversion', 'current_version', 'version'],
    fixedVersion: ['fixedversion', 'fixed_version', 'fixversion', 'fix_version', 'patchedversion', 'patched_version', 'remediation_version'],
    status: ['status', 'vulnerability_status', 'state'],
    remediation: ['remediation', 'solution', 'fix', 'recommendation'],
  },
};

// Section container key aliases for JSON & LOG
export const SECTION_ALIASES: Record<string, string[]> = {
  yara: ['yara', 'yararesults', 'yara_results', 'yaramatches', 'yara_matches', 'yararules', 'yara_rules', 'rules', 'yarasignatures', 'yara_signatures'],
  virusTotal: ['virustotal', 'virustotalresult', 'virustotal_result', 'vt', 'vtresult', 'vt_result', 'vtresults', 'vt_results', 'virustotalsimulated', 'virustotal_simulated'],
  iocs: ['iocs', 'indicators', 'ioclist', 'ioc_list', 'iocresults', 'ioc_results', 'observables', 'threatindicators', 'threat_indicators', 'networkindicators', 'network_indicators', 'networkindicatorssimulated', 'network_indicators_simulated'],
  mitre: ['mitre', 'mitretechniques', 'mitre_techniques', 'mitreattack', 'mitre_attack', 'attacktechniques', 'attack_techniques', 'techniques'],
  behavior: ['behavior', 'behaviorevents', 'behavior_events', 'behavioral_events', 'eventsbehavior', 'events_behavior', 'behavioranalysis', 'behavior_analysis'],
  sandbox: ['sandbox', 'sandboxresults', 'sandbox_results', 'sandboxruns', 'sandbox_runs', 'sandboxanalysis', 'sandbox_analysis'],
  siem: ['siem', 'siemevents', 'siem_events', 'siemlogs', 'siem_logs', 'logs', 'syslog', 'records', 'entries', 'security_events', 'securityevents', 'audit_logs', 'auditlogs', 'telemetry', 'event_logs', 'eventlogs'],
  incident: ['incident', 'incidents', 'incidentlist', 'incident_list'],
  soar: ['soar', 'soarexecutions', 'soar_executions', 'soaractions', 'soar_actions', 'playbooks', 'actions'],
  assets: ['assets', 'assetlist', 'asset_list', 'inventoryassets', 'inventory_assets', 'inventory'],
  endpoints: ['endpoints', 'endpointlist', 'endpoint_list', 'devices'],
  vulnerabilities: ['vulnerabilities', 'vulnerabilitylist', 'vulnerability_list', 'vulnerabilitieslist', 'cves', 'vulns', 'flaws', 'cverecords', 'cve_records'],
};

export function findValueByAliases(obj: any, aliases: string[], primitiveOnly = false): any {
  if (!obj || typeof obj !== 'object') return undefined;

  for (const alias of aliases) {
    const normAlias = normalizeKey(alias);
    for (const key of Object.keys(obj)) {
      if (normalizeKey(key) === normAlias && obj[key] !== undefined && obj[key] !== null && obj[key] !== '') {
        const val = obj[key];
        if (primitiveOnly && typeof val === 'object') {
          continue;
        }
        return val;
      }
    }
  }
  return undefined;
}

export function classifyItemEntity(item: Record<string, any>): string | null {
  if (!item || typeof item !== 'object') return null;

  const keys = Object.keys(item).map(normalizeKey);
  const keySet = new Set(keys);

  // 1. Vulnerability
  if (
    keySet.has('cveid') || keySet.has('cve') || keySet.has('vulnerabilityid') || keySet.has('vulnid') ||
    keySet.has('cvssscore') || keySet.has('cvss') || keySet.has('packagename') || keySet.has('vulnerabilitytitle')
  ) {
    return 'vulnerabilities';
  }

  // 2. YARA
  if (keySet.has('rulename') || keySet.has('yararule') || keySet.has('yara_rule') || (keySet.has('rule') && (keySet.has('meta') || keySet.has('tags') || keySet.has('namespace')))) {
    return 'yara';
  }

  // 3. MITRE
  if (keySet.has('techniqueid') || keySet.has('mitreid') || keySet.has('attackid') || (keySet.has('tactic') && keySet.has('technique'))) {
    return 'mitre';
  }

  // 4. Sandbox
  if (keySet.has('sandboxname') || keySet.has('verdict') || (keySet.has('sandbox') && keySet.has('score'))) {
    return 'sandbox';
  }

  // 5. SOAR
  if (keySet.has('actionname') || keySet.has('playbook') || keySet.has('executionlog') || keySet.has('actiontype')) {
    return 'soar';
  }

  // Distinct check for SIEM indicators vs behavior/IOCs
  const hasSiemIndicators =
    keySet.has('sourceip') || keySet.has('destip') || keySet.has('rawevent') || keySet.has('eventid') ||
    keySet.has('srcip') || keySet.has('dstip') || keySet.has('clientip') || keySet.has('serverip') ||
    keySet.has('src') || keySet.has('dst') || keySet.has('sport') || keySet.has('dport') ||
    keySet.has('spt') || keySet.has('dpt') || keySet.has('protocol') || keySet.has('proto') ||
    keySet.has('rawlog') || keySet.has('log') || keySet.has('sigid') || keySet.has('signatureid') ||
    ((keySet.has('timestamp') || keySet.has('time') || keySet.has('date') || keySet.has('datetime')) &&
      (keySet.has('message') || keySet.has('msg') || keySet.has('action') || keySet.has('level') || keySet.has('severity') || keySet.has('status')));

  // 6. SIEM (prioritize when network/log telemetry indicators are present)
  if (
    hasSiemIndicators ||
    ((keySet.has('message') || keySet.has('msg') || keySet.has('log')) &&
      (keySet.has('level') || keySet.has('severity') || keySet.has('action') || keySet.has('protocol') || keySet.has('status')))
  ) {
    return 'siem';
  }

  // 7. Behavior (process execution, persistence, registry modifications)
  if (keySet.has('eventtype') || (keySet.has('action') && keySet.has('target')) || keySet.has('behavioraction')) {
    return 'behavior';
  }

  // 8. Asset
  if (keySet.has('assetname') || keySet.has('macaddress') || keySet.has('criticality') || keySet.has('assettype')) {
    return 'assets';
  }

  // 9. Endpoint
  if (keySet.has('osversion') || keySet.has('agentstatus') || keySet.has('endpointtype') || keySet.has('lastseen')) {
    return 'endpoints';
  }

  // 10. IOC
  if (keySet.has('ioctype') || keySet.has('iocvalue') || keySet.has('indicator') || keySet.has('indicatortype') || keySet.has('indicatorvalue') || (keySet.has('type') && keySet.has('value') && !keySet.has('action'))) {
    return 'iocs';
  }

  // 11. Incident
  if (keySet.has('title') && (keySet.has('severity') || keySet.has('reason') || keySet.has('assignedto'))) {
    return 'incident';
  }

  return null;
}
