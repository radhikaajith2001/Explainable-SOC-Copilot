import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, Clock, User, Server, Eye, Book, Target, BarChart3, ChevronDown, ChevronUp, RefreshCw, Wifi, WifiOff, ExternalLink, Database, Globe, Bug, FileText, Lock } from 'lucide-react';

const SOCCopilot = () => {
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [expandedSections, setExpandedSections] = useState({
    explanation: true,
    confidence: true,
    mitre: true,
    playbook: true,
    liveData: true,
    feeds: true
  });
  const [threatIntelSources, setThreatIntelSources] = useState([]);
  const [isConnected, setIsConnected] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [lastUpdate, setLastUpdate] = useState(null);
  const [connectionStatus, setConnectionStatus] = useState('disconnected');
  const [feedStatus, setFeedStatus] = useState({});
  const [simulatedDataset, setSimulatedDataset] = useState('CICIDS2017');

  // Realistic SIEM alert data based on public datasets
  const [siemAlerts, setSiemAlerts] = useState([]);

  // Generate realistic alerts based on selected dataset
  const generateAlertsFromDataset = (dataset) => {
    const baseAlerts = {
      'CICIDS2017': [
        {
          id: "ALR-2024-001",
          timestamp: new Date().toLocaleString(),
          source: "Splunk BOTS Dataset",
          severity: "HIGH",
          title: "DridexMalware C2 Communication Detected",
          rawData: {
            source_ip: "192.168.1.105",
            destination_ip: "185.159.158.69", // Real Feodo Tracker C2
            destination_port: 8443,
            protocol: "TCP",
            bytes_out: 45632,
            flow_duration: 847,
            packet_count: 234,
            malware_family: "Dridex"
          },
          dataset_context: "CICIDS 2017 - Botnet communication pattern",
          explanation: {
            summary: "Detected communication pattern matching Dridex banking trojan C2 infrastructure.",
            why_flagged: "Traffic to known C2 server listed in Feodo Tracker with SSL encryption on non-standard port.",
            attack_vector: "Infected endpoint establishing persistent connection to command and control server.",
            context: "This matches the SSL-encrypted C2 communication pattern typical of Dridex malware operations."
          }
        },
        {
          id: "ALR-2024-002", 
          timestamp: new Date(Date.now() - 300000).toLocaleString(),
          source: "Azure Sentinel",
          severity: "MEDIUM",
          title: "Suspicious Domain Query Pattern",
          rawData: {
            hostname: "workstation-42",
            dns_queries: ["evil-domain.tk", "malware-c2.ml", "phishing-site.ga"],
            query_count: 15,
            user: "alice.johnson",
            resolver: "8.8.8.8",
            query_type: "A"
          },
          dataset_context: "URLhaus malicious domain correlation",
          explanation: {
            summary: "Multiple DNS queries to domains flagged in URLhaus threat intelligence feed.",
            why_flagged: "Domains match known malware distribution and phishing campaigns in threat feeds.",
            attack_vector: "Potential malware attempting to resolve C2 infrastructure or user accessing phishing sites.",
            context: "Pattern suggests either malware infection or social engineering attack in progress."
          }
        },
        {
          id: "ALR-2024-003",
          timestamp: new Date(Date.now() - 600000).toLocaleString(), 
          source: "Elastic SIEM",
          severity: "HIGH",
          title: "Malicious File Hash Detected",
          rawData: {
            filename: "invoice_2024.exe",
            file_hash: "d4f4c8e9a6b7c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8",
            file_size: 2048576,
            execution_path: "C:\\Users\\bob\\Downloads\\",
            process_name: "invoice_2024.exe",
            parent_process: "outlook.exe"
          },
          dataset_context: "MalwareBazaar sample correlation",
          explanation: {
            summary: "Executable file matches known malware hash in MalwareBazaar database.",
            why_flagged: "SHA256 hash identified as malware sample with high confidence rating.",
            attack_vector: "Email-delivered malware sample, likely phishing attachment execution.",
            context: "File originated from email client, typical delivery method for malware campaigns."
          }
        }
      ],
      'UNSW-NB15': [
        {
          id: "ALR-2024-004",
          timestamp: new Date(Date.now() - 900000).toLocaleString(),
          source: "Network IDS",
          severity: "HIGH", 
          title: "Reconnaissance Scanning Activity",
          rawData: {
            source_ip: "203.176.135.102", // GreyNoise scanner IP
            scan_type: "TCP SYN",
            ports_scanned: [22, 80, 443, 3389, 445],
            scan_duration: 300,
            packets_sent: 1250,
            target_range: "10.0.0.0/24"
          },
          dataset_context: "UNSW-NB15 reconnaissance attack pattern",
          explanation: {
            summary: "External IP conducting systematic port scanning of internal network range.",
            why_flagged: "High-speed scanning pattern targeting common service ports across network range.",
            attack_vector: "Network reconnaissance phase, likely precursor to targeted exploitation attempts.",
            context: "Scanning pattern consistent with automated attack tools and frameworks."
          }
        }
      ],
      'CTU-13': [
        {
          id: "ALR-2024-005",
          timestamp: new Date(Date.now() - 1200000).toLocaleString(),
          source: "NetFlow Analysis",
          severity: "MEDIUM",
          title: "Botnet NetFlow Pattern Detected", 
          rawData: {
            source_ip: "192.168.1.87",
            botnet_family: "Zeus",
            flow_pattern: "periodic_beaconing",
            beacon_interval: 3600,
            destination_ips: ["91.199.212.100", "94.102.49.190"],
            total_flows: 847,
            avg_bytes_per_flow: 1024
          },
          dataset_context: "CTU-13 botnet traffic analysis",
          explanation: {
            summary: "NetFlow analysis reveals periodic communication pattern consistent with botnet activity.",
            why_flagged: "Regular beaconing intervals and small payload sizes match Zeus botnet signatures.",
            attack_vector: "Infected endpoint participating in botnet infrastructure for data theft or spam.",
            context: "Traffic pattern analysis from CTU-13 dataset shows classic bot behavior."
          }
        }
      ]
    };
    return baseAlerts[dataset] || baseAlerts['CICIDS2017'];
  };

  // Real threat intelligence feed connections
  const fetchRealThreatIntel = async () => {
    setIsLoading(true);
    setConnectionStatus('connecting');
    const sources = [];
    const status = {};

    try {
      // 1. Abuse.ch Feodo Tracker (C2 IPs)
      try {
        const feodoResponse = await fetch('https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt', {
          mode: 'cors',
          headers: {
            'User-Agent': 'SOC-Copilot/1.0'
          }
        });
        if (feodoResponse.ok) {
          const feodoText = await feodoResponse.text();
          const ips = feodoText.split('\n')
            .filter(line => line && !line.startsWith('#'))
            .slice(0, 10); // Take first 10 for demo
          
          sources.push({
            name: 'Feodo Tracker (C2 IPs)',
            type: 'c2_ips',
            count: ips.length,
            sample_data: ips.slice(0, 3),
            source: 'abuse.ch',
            last_updated: new Date().toISOString(),
            status: 'active'
          });
          status['feodo'] = 'connected';
        }
      } catch (e) {
        status['feodo'] = 'error';
        console.log('Feodo Tracker unavailable (CORS)');
      }

      // 2. URLhaus (Malicious URLs) - Using their API
      try {
        const urlhausResponse = await fetch('https://urlhaus-api.abuse.ch/v1/urls/recent/', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ limit: 10 })
        });
        
        if (urlhausResponse.ok) {
          const urlhausData = await urlhausResponse.json();
          sources.push({
            name: 'URLhaus (Malicious URLs)',
            type: 'malicious_urls',
            count: urlhausData.urls?.length || 0,
            sample_data: urlhausData.urls?.slice(0, 3).map(u => u.url) || [],
            source: 'abuse.ch',
            last_updated: new Date().toISOString(),
            status: 'active'
          });
          status['urlhaus'] = 'connected';
        }
      } catch (e) {
        status['urlhaus'] = 'error';
        console.log('URLhaus API unavailable');
      }

      // 3. MalwareBazaar (File Hashes)
      try {
        const malwareResponse = await fetch('https://mb-api.abuse.ch/api/v1/', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            query: 'get_recent',
            selector: 'time'
          })
        });

        if (malwareResponse.ok) {
          const malwareData = await malwareResponse.json();
          sources.push({
            name: 'MalwareBazaar (File Hashes)',
            type: 'file_hashes', 
            count: malwareData.data?.length || 0,
            sample_data: malwareData.data?.slice(0, 3).map(m => m.sha256_hash) || [],
            source: 'abuse.ch',
            last_updated: new Date().toISOString(),
            status: 'active'
          });
          status['malwarebazaar'] = 'connected';
        }
      } catch (e) {
        status['malwarebazaar'] = 'error';
        console.log('MalwareBazaar API unavailable');
      }

      // 4. Simulated connections for APIs that require keys
      const simulatedSources = [
        {
          name: 'AlienVault OTX',
          type: 'mixed_iocs',
          count: 1247,
          sample_data: ['malicious-domain.com', '185.159.158.69', 'trojan.exe'],
          source: 'otx.alienvault.com',
          last_updated: new Date().toISOString(),
          status: 'simulated',
          note: 'Requires API key for real connection'
        },
        {
          name: 'VirusTotal Public API',
          type: 'reputation_data',
          count: 856,
          sample_data: ['23/70 engines detected', '45/70 engines detected'],
          source: 'virustotal.com',
          last_updated: new Date().toISOString(), 
          status: 'simulated',
          note: 'Rate limited - requires API key'
        },
        {
          name: 'GreyNoise Community',
          type: 'internet_noise',
          count: 2341,
          sample_data: ['Scanner: Shodan.io', 'Benign: GoogleBot', 'Malicious: Mirai'],
          source: 'greynoise.io',
          last_updated: new Date().toISOString(),
          status: 'simulated',
          note: 'Requires API key for full access'
        },
        {
          name: 'MISP Open Feeds',
          type: 'threat_events',
          count: 567,
          sample_data: ['APT29 Campaign', 'Ransomware IOCs', 'Phishing Campaign'],
          source: 'misp-project.org',
          last_updated: new Date().toISOString(),
          status: 'simulated',
          note: 'Multiple community feeds available'
        }
      ];

      sources.push(...simulatedSources);
      
      setThreatIntelSources(sources);
      setFeedStatus(status);
      setIsConnected(sources.length > 0);
      setConnectionStatus('connected');
      setLastUpdate(new Date());

      // Update alerts with threat intelligence context
      const currentAlerts = generateAlertsFromDataset(simulatedDataset);
      const enrichedAlerts = currentAlerts.map(alert => {
        // Match IOCs from threat feeds
        const matchedSources = sources.filter(source => {
          if (source.type === 'c2_ips' && alert.rawData.destination_ip) {
            return source.sample_data.includes(alert.rawData.destination_ip);
          }
          if (source.type === 'malicious_urls' && alert.rawData.dns_queries) {
            return alert.rawData.dns_queries.some(domain => 
              source.sample_data.some(url => url.includes(domain))
            );
          }
          if (source.type === 'file_hashes' && alert.rawData.file_hash) {
            return source.sample_data.includes(alert.rawData.file_hash);
          }
          return false;
        });

        return {
          ...alert,
          threatIntelMatches: matchedSources,
          confidence: {
            ...alert.confidence,
            score: matchedSources.length > 0 ? Math.min(95, alert.confidence?.score + 15) : alert.confidence?.score || 75
          }
        };
      });

      setSiemAlerts(enrichedAlerts);

    } catch (error) {
      console.error('Failed to fetch threat intelligence:', error);
      setConnectionStatus('error');
      setIsConnected(false);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    // Initial load
    setSiemAlerts(generateAlertsFromDataset(simulatedDataset));
    fetchRealThreatIntel();
    
    // Auto-refresh every 10 minutes
    const interval = setInterval(fetchRealThreatIntel, 600000);
    return () => clearInterval(interval);
  }, [simulatedDataset]);

  const toggleSection = (section) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  const getSeverityColor = (severity) => {
    switch(severity) {
      case 'HIGH': return 'text-red-600 bg-red-100';
      case 'MEDIUM': return 'text-orange-600 bg-orange-100'; 
      case 'LOW': return 'text-yellow-600 bg-yellow-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getConfidenceColor = (score) => {
    if (score >= 80) return 'text-red-600';
    if (score >= 60) return 'text-orange-600';
    if (score >= 40) return 'text-yellow-600';
    return 'text-green-600';
  };

  const getConnectionStatusColor = (status) => {
    switch(status) {
      case 'connected': return 'text-green-600';
      case 'connecting': return 'text-yellow-600';
      case 'error': return 'text-red-600';
      default: return 'text-gray-600';
    }
  };

  const getSourceIcon = (type) => {
    switch(type) {
      case 'c2_ips': return <Server className="h-4 w-4" />;
      case 'malicious_urls': return <Globe className="h-4 w-4" />;
      case 'file_hashes': return <FileText className="h-4 w-4" />;
      case 'mixed_iocs': return <Database className="h-4 w-4" />;
      case 'reputation_data': return <Shield className="h-4 w-4" />;
      case 'internet_noise': return <Bug className="h-4 w-4" />;
      case 'threat_events': return <Target className="h-4 w-4" />;
      default: return <Database className="h-4 w-4" />;
    }
  };

  return (
    <div className="max-w-7xl mx-auto p-6 bg-gray-50 min-h-screen">
      <div className="mb-8">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <Shield className="h-8 w-8 text-blue-600" />
            <h1 className="text-3xl font-bold text-gray-900">Real-World SOC Copilot</h1>
          </div>
          
          <div className="flex items-center gap-4">
            {/* Dataset Selector */}
            <select 
              value={simulatedDataset}
              onChange={(e) => setSimulatedDataset(e.target.value)}
              className="px-3 py-1 border border-gray-300 rounded-md text-sm"
            >
              <option value="CICIDS2017">CICIDS 2017 Dataset</option>
              <option value="UNSW-NB15">UNSW-NB15 Dataset</option>
              <option value="CTU-13">CTU-13 Botnet Dataset</option>
            </select>

            {/* Connection Status */}
            <div className="flex items-center gap-2">
              {isConnected ? <Wifi className="h-4 w-4 text-green-600" /> : <WifiOff className="h-4 w-4 text-red-600" />}
              <span className={`text-sm font-medium ${getConnectionStatusColor(connectionStatus)}`}>
                {connectionStatus === 'connected' && `${threatIntelSources.length} Threat Feeds`}
                {connectionStatus === 'connecting' && 'Connecting...'}
                {connectionStatus === 'error' && 'Connection Error'}
                {connectionStatus === 'disconnected' && 'Disconnected'}
              </span>
            </div>
            
            <button
              onClick={fetchRealThreatIntel}
              disabled={isLoading}
              className="flex items-center gap-2 px-3 py-1 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50"
            >
              <RefreshCw className={`h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
              Refresh Feeds
            </button>
          </div>
        </div>
        <p className="text-gray-600 text-lg">Real threat intelligence integration with public security datasets</p>
        {lastUpdate && (
          <p className="text-sm text-gray-500 mt-1">
            Last updated: {lastUpdate.toLocaleString()} • Dataset: {simulatedDataset}
          </p>
        )}
      </div>

      {/* Threat Intelligence Sources */}
      <div className="bg-white rounded-lg shadow-md mb-6">
        <div className="p-4 border-b cursor-pointer" onClick={() => toggleSection('feeds')}>
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-semibold flex items-center gap-2">
              <Database className="h-5 w-5 text-blue-600" />
              Active Threat Intelligence Feeds ({threatIntelSources.length})
            </h3>
            {expandedSections.feeds ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
          </div>
        </div>
        {expandedSections.feeds && (
          <div className="p-4">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {threatIntelSources.map((source, index) => (
                <div key={index} className="border border-gray-200 rounded-lg p-3">
                  <div className="flex justify-between items-start mb-2">
                    <div className="flex items-center gap-2">
                      {getSourceIcon(source.type)}
                      <span className="font-semibold text-sm">{source.name}</span>
                    </div>
                    <span className={`px-2 py-1 rounded text-xs font-medium ${
                      source.status === 'active' ? 'bg-green-100 text-green-700' :
                      source.status === 'simulated' ? 'bg-blue-100 text-blue-700' :
                      'bg-red-100 text-red-700'
                    }`}>
                      {source.status}
                    </span>
                  </div>
                  
                  <div className="text-xs text-gray-600 mb-2">
                    <div>Count: {source.count.toLocaleString()}</div>
                    <div>Source: {source.source}</div>
                  </div>
                  
                  {source.sample_data && source.sample_data.length > 0 && (
                    <div className="text-xs">
                      <div className="font-medium mb-1">Sample IOCs:</div>
                      <div className="space-y-1">
                        {source.sample_data.slice(0, 2).map((sample, idx) => (
                          <div key={idx} className="bg-gray-100 p-1 rounded font-mono text-xs truncate">
                            {sample}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                  
                  {source.note && (
                    <div className="text-xs text-blue-600 mt-2 italic">
                      {source.note}
                    </div>
                  )}
                </div>
              ))}
            </div>
            
            {threatIntelSources.length === 0 && (
              <div className="text-center py-8">
                <Database className="h-12 w-12 text-gray-400 mx-auto mb-2" />
                <div className="text-gray-500">
                  {isLoading ? 'Loading threat intelligence feeds...' : 'No threat intelligence feeds available'}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Alert List */}
        <div className="lg:col-span-1">
          <div className="bg-white rounded-lg shadow-md p-4">
            <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
              <AlertTriangle className="h-5 w-5" />
              Dataset Alerts ({siemAlerts.length})
            </h2>
            <div className="space-y-3">
              {siemAlerts.map((alert) => (
                <div
                  key={alert.id}
                  className={`p-3 border rounded-lg cursor-pointer transition-all ${
                    selectedAlert?.id === alert.id 
                      ? 'border-blue-500 bg-blue-50' 
                      : 'border-gray-200 hover:border-gray-300'
                  }`}
                  onClick={() => setSelectedAlert(alert)}
                >
                  <div className="flex justify-between items-start mb-2">
                    <span className="font-medium text-sm">{alert.id}</span>
                    <div className="flex items-center gap-2">
                      {alert.threatIntelMatches && alert.threatIntelMatches.length > 0 && (
                        <span className="flex items-center gap-1">
                          <div className="w-2 h-2 bg-red-500 rounded-full animate-pulse"></div>
                          <span className="text-xs text-red-600">{alert.threatIntelMatches.length}</span>
                        </span>
                      )}
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(alert.severity)}`}>
                        {alert.severity}
                      </span>
                    </div>
                  </div>
                  <h3 className="font-semibold text-gray-900 mb-1">{alert.title}</h3>
                  <div className="flex items-center gap-2 text-xs text-gray-500">
                    <Clock className="h-3 w-3" />
                    {alert.timestamp}
                  </div>
                  <div className="flex items-center gap-2 text-xs text-gray-500 mt-1">
                    <Server className="h-3 w-3" />
                    {alert.source}
                  </div>
                  {alert.dataset_context && (
                    <div className="text-xs text-blue-600 mt-1">
                      📊 {alert.dataset_context}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Alert Analysis */}
        <div className="lg:col-span-2">
          {selectedAlert ? (
            <div className="space-y-6">
              {/* Alert Header with Threat Intel Matches */}
              <div className="bg-white rounded-lg shadow-md p-6">
                <div className="flex justify-between items-start mb-4">
                  <h2 className="text-2xl font-bold text-gray-900">{selectedAlert.title}</h2>
                  <div className="flex items-center gap-2">
                    {selectedAlert.threatIntelMatches && selectedAlert.threatIntelMatches.length > 0 && (
                      <span className="px-2 py-1 bg-red-100 text-red-700 rounded text-xs font-medium">
                        {selectedAlert.threatIntelMatches.length} INTEL MATCHES
                      </span>
                    )}
                    <span className={`px-3 py-1 rounded-full text-sm font-medium ${getSeverityColor(selectedAlert.severity)}`}>
                      {selectedAlert.severity}
                    </span>
                  </div>
                </div>
                
                {/* Threat Intel Matches */}
                {selectedAlert.threatIntelMatches && selectedAlert.threatIntelMatches.length > 0 && (
                  <div className="mb-4 p-4 bg-red-50 border border-red-200 rounded-lg">
                    <h4 className="font-semibold text-red-800 mb-2 flex items-center gap-2">
                      <Target className="h-4 w-4" />
                      Threat Intelligence Matches
                    </h4>
                    <div className="space-y-2">
                      {selectedAlert.threatIntelMatches.map((match, index) => (
                        <div key={index} className="flex justify-between items-center p-2 bg-white rounded border">
                          <div className="flex items-center gap-2">
                            {getSourceIcon(match.type)}
                            <span className="font-medium">{match.name}</span>
                          </div>
                          <span className="text-xs text-red-600">
                            {match.status === 'active' ? 'LIVE FEED' : 'SIMULATED'}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                
                <div className="grid grid-cols-2 gap-4 text-sm text-gray-600">
                  <div><strong>Alert ID:</strong> {selectedAlert.id}</div>
                  <div><strong>Source:</strong> {selectedAlert.source}</div>
                  <div><strong>Dataset:</strong> {selectedAlert.dataset_context}</div>
                  <div><strong>Confidence:</strong> 
                    <span className={`ml-2 font-semibold ${getConfidenceColor(selectedAlert.confidence?.score || 75)}`}>
                      {selectedAlert.confidence?.score || 75}%
                    </span>
                  </div>
                </div>
              </div>

              {/* AI Explanation Enhanced with Dataset Context */}
              <div className="bg-white rounded-lg shadow-md">
                <div className="p-4 border-b cursor-pointer" onClick={() => toggleSection('explanation')}>
                  <div className="flex justify-between items-center">
                    <h3 className="text-lg font-semibold flex items-center gap-2">
                      <Eye className="h-5 w-5 text-blue-600" />
                      AI Analysis - Dataset: {simulatedDataset}
                    </h3>
                    {expandedSections.explanation ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                  </div>
                </div>
                {expandedSections.explanation && (
                  <div className="p-4">
                    <div className="space-y-4">
                      <div>
                        <h4 className="font-semibold text-gray-900 mb-2">Summary</h4>
                        <p className="text-gray-700">{selectedAlert.explanation.summary}</p>
                      </div>
                      <div>
                        <h4 className="font-semibold text-gray-900 mb-2">Why This Was Flagged</h4>
                        <p className="text-gray-700">{selectedAlert.explanation.why_flagged}</p>
                      </div>
                      <div>
                        <h4 className="font-semibold text-gray-900 mb-2">Attack Vector</h4>
                        <p className="text-gray-700">{selectedAlert.explanation.attack_vector}</p>
                      </div>
                      <div>
                        <h4 className="font-semibold text-gray-900 mb-2">Dataset Context</h4>
                        <p className="text-gray-700">{selectedAlert.explanation.context}</p>
                        <div className="mt-2 p-2 bg-blue-50 rounded border-l-4 border-blue-400">
                          <p className="text-sm text-blue-800">
                            <strong>Dataset Source:</strong> {selectedAlert.dataset_context}
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Raw Data Display */}
              <div className="bg-white rounded-lg shadow-md">
                <div className="p-4 border-b">
                  <h3 className="text-lg font-semibold flex items-center gap-2">
                    <Database className="h-5 w-5 text-gray-600" />
                    Raw Alert Data
                  </h3>
                </div>
                <div className="p-4">
                  <div className="bg-gray-100 rounded-lg p-4 overflow-x-auto">
                    <pre className="text-sm">
                      {JSON.stringify(selectedAlert.rawData, null, 2)}
                    </pre>
                  </div>
                </div>
              </div>

              {/* Response Actions */}
              <div className="bg-white rounded-lg shadow-md">
                <div className="p-4 border-b">
                  <h3 className="text-lg font-semibold flex items-center gap-2">
                    <Book className="h-5 w-5 text-purple-600" />
                    Recommended Actions
                  </h3>
                </div>
                <div className="p-4">
                  <div className="space-y-3">
                    <div className="flex items-center gap-3 p-3 bg-red-50 rounded-lg">
                      <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                      <span className="font-medium">High Priority:</span>
                      <span>Block malicious IOCs immediately</span>
                    </div>
                    <div className="flex items-center gap-3 p-3 bg-orange-50 rounded-lg">
                      <div className="w-3 h-3 bg-orange-500 rounded-full"></div>
                      <span className="font-medium">Medium Priority:</span>
                      <span>Isolate affected systems</span>
                    </div>
                    <div className="flex items-center gap-3 p-3 bg-blue-50 rounded-lg">
                      <div className="w-3 h-3 bg-blue-500 rounded-full"></div>
                      <span className="font-medium">Investigation:</span>
                      <span>Correlate with additional threat feeds</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-white rounded-lg shadow-md p-8 text-center">
              <Shield className="h-16 w-16 text-gray-400 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-gray-700 mb-2">Select an Alert</h3>
              <p className="text-gray-500">
                Choose an alert to see detailed analysis with real threat intelligence correlation.
              </p>
              <p className="text-sm text-gray-400 mt-2">
                Currently using {simulatedDataset} dataset with live threat feeds integration.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default SOCCopilot;