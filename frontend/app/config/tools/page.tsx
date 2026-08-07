'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { api } from '@/lib/tauri-api';
import type { ToolsConfig, AgentsConfig, AgentConfig, Severity } from '@/lib/types';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { Skeleton } from '@/components/ui/skeleton';
import { Switch } from '@/components/ui/switch';
import { Slider } from '@/components/ui/slider';
import { Checkbox } from '@/components/ui/checkbox';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from '@/components/ui/accordion';
import { toast } from 'sonner';
import {
  ArrowLeft,
  Wrench,
  Users,
  Search,
  Radar,
  Globe,
  Code,
  Shield,
  Save,
  RotateCcw,
  Info,
  Zap,
  Terminal,
  FileSearch,
  Bug,
  Lock,
} from 'lucide-react';

// Default configurations
const DEFAULT_NMAP_CONFIG = {
  default_ports: '1-1000',
  timing_template: 4,
  max_rate: 1000,
};

const DEFAULT_NUCLEI_CONFIG = {
  templates: ['cve', 'owasp-top-10', 'vulnerabilities', 'misconfiguration'],
  severity: 'medium,high,critical',
  rate_limit: 150,
  bulk_size: 25,
  concurrency: 25,
  custom_templates_path: '',
};

const DEFAULT_SQLMAP_CONFIG = {
  level: 2,
  risk: 1,
  threads: 4,
  technique: 'BEUSTQ',
};

const DEFAULT_FFUF_CONFIG = {
  wordlist: '/opt/pentest/wordlists/common.txt',
  rate: 100,
  timeout: 10,
};

const DEFAULT_METASPLOIT_CONFIG = {
  check_mode: true,
  threads: 4,
};

const DEFAULT_SEMGREP_CONFIG = {
  rulesets: ['p/security-audit', 'p/owasp-top-ten'],
  severity: 'warning',
  timeout: 300,
};

const DEFAULT_AGENTS_CONFIG: AgentsConfig = {
  recon: { enabled: true, timeout_minutes: 30, auto_start: false, requires_approval: false },
  'vuln-scan': { enabled: true, timeout_minutes: 60, auto_start: false, requires_approval: false },
  'web-app': { enabled: true, timeout_minutes: 45, auto_start: false, requires_approval: false },
  exploit: { enabled: true, timeout_minutes: 30, auto_start: false, requires_approval: true },
  'security-scan': { enabled: true, timeout_minutes: 30, auto_start: false, requires_approval: false },
  report: { enabled: true, timeout_minutes: 15, auto_start: false, requires_approval: false },
};

const NUCLEI_TEMPLATE_OPTIONS = [
  { value: 'cve', label: 'CVEs', description: 'Known vulnerability exploits' },
  { value: 'owasp-top-10', label: 'OWASP Top 10', description: 'Common web vulnerabilities' },
  { value: 'vulnerabilities', label: 'Vulnerabilities', description: 'General vulnerability checks' },
  { value: 'misconfiguration', label: 'Misconfigurations', description: 'Security misconfigurations' },
  { value: 'exposures', label: 'Exposures', description: 'Sensitive data exposures' },
  { value: 'technologies', label: 'Technologies', description: 'Technology fingerprinting' },
  { value: 'default-logins', label: 'Default Logins', description: 'Default credential checks' },
  { value: 'file', label: 'File Inclusion', description: 'LFI/RFI vulnerabilities' },
  { value: 'fuzzing', label: 'Fuzzing', description: 'Fuzzing templates' },
];

const SEMGREP_RULESET_OPTIONS = [
  { value: 'p/security-audit', label: 'Security Audit', description: 'Comprehensive security rules' },
  { value: 'p/owasp-top-ten', label: 'OWASP Top 10', description: 'OWASP vulnerability patterns' },
  { value: 'p/secrets', label: 'Secrets', description: 'Hardcoded secrets detection' },
  { value: 'p/sql-injection', label: 'SQL Injection', description: 'SQL injection patterns' },
  { value: 'p/xss', label: 'XSS', description: 'Cross-site scripting patterns' },
  { value: 'p/command-injection', label: 'Command Injection', description: 'OS command injection' },
  { value: 'p/insecure-transport', label: 'Insecure Transport', description: 'HTTP/TLS issues' },
];

export default function ToolsConfigPage() {
  const router = useRouter();
  const queryClient = useQueryClient();

  // Tool configs state
  const [nmapConfig, setNmapConfig] = useState(DEFAULT_NMAP_CONFIG);
  const [nucleiConfig, setNucleiConfig] = useState(DEFAULT_NUCLEI_CONFIG);
  const [sqlmapConfig, setSqlmapConfig] = useState(DEFAULT_SQLMAP_CONFIG);
  const [ffufConfig, setFfufConfig] = useState(DEFAULT_FFUF_CONFIG);
  const [metasploitConfig, setMetasploitConfig] = useState(DEFAULT_METASPLOIT_CONFIG);
  const [semgrepConfig, setSemgrepConfig] = useState(DEFAULT_SEMGREP_CONFIG);
  const [agentsConfig, setAgentsConfig] = useState<AgentsConfig>(DEFAULT_AGENTS_CONFIG);

  const [hasChanges, setHasChanges] = useState(false);

  // Fetch current configs
  const { data: toolsConfig, isLoading: toolsLoading } = useQuery({
    queryKey: ['tools-config'],
    queryFn: () => api.config.tools.get(),
  });

  const { data: fetchedAgentsConfig, isLoading: agentsLoading } = useQuery({
    queryKey: ['agents-config'],
    queryFn: () => api.config.agents.get(),
  });

  // Load configs into state
  useEffect(() => {
    if (toolsConfig) {
      if (toolsConfig.nmap) setNmapConfig({ ...DEFAULT_NMAP_CONFIG, ...toolsConfig.nmap });
      if (toolsConfig.nuclei) setNucleiConfig({ ...DEFAULT_NUCLEI_CONFIG, ...toolsConfig.nuclei });
      if (toolsConfig.sqlmap) setSqlmapConfig({ ...DEFAULT_SQLMAP_CONFIG, ...toolsConfig.sqlmap });
      if (toolsConfig.ffuf) setFfufConfig({ ...DEFAULT_FFUF_CONFIG, ...toolsConfig.ffuf });
      if (toolsConfig.metasploit) setMetasploitConfig({ ...DEFAULT_METASPLOIT_CONFIG, ...toolsConfig.metasploit });
      if (toolsConfig.semgrep) setSemgrepConfig({ ...DEFAULT_SEMGREP_CONFIG, ...toolsConfig.semgrep });
    }
  }, [toolsConfig]);

  useEffect(() => {
    if (fetchedAgentsConfig) {
      setAgentsConfig({ ...DEFAULT_AGENTS_CONFIG, ...fetchedAgentsConfig });
    }
  }, [fetchedAgentsConfig]);

  // Save mutations
  const saveToolsMutation = useMutation({
    mutationFn: (config: ToolsConfig) => api.config.tools.update(config),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tools-config'] });
      toast.success('Tool configuration saved');
      setHasChanges(false);
    },
    onError: (error: Error) => {
      toast.error(`Failed to save: ${error.message}`);
    },
  });

  const saveAgentsMutation = useMutation({
    mutationFn: (config: AgentsConfig) => api.config.agents.update(config),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['agents-config'] });
      toast.success('Agent configuration saved');
      setHasChanges(false);
    },
    onError: (error: Error) => {
      toast.error(`Failed to save: ${error.message}`);
    },
  });

  const handleSaveTools = () => {
    saveToolsMutation.mutate({
      nmap: nmapConfig,
      nuclei: nucleiConfig,
      sqlmap: sqlmapConfig,
      ffuf: ffufConfig,
      metasploit: metasploitConfig,
      semgrep: semgrepConfig,
    } as ToolsConfig);
  };

  const handleSaveAgents = () => {
    saveAgentsMutation.mutate(agentsConfig);
  };

  const handleResetTools = () => {
    setNmapConfig(DEFAULT_NMAP_CONFIG);
    setNucleiConfig(DEFAULT_NUCLEI_CONFIG);
    setSqlmapConfig(DEFAULT_SQLMAP_CONFIG);
    setFfufConfig(DEFAULT_FFUF_CONFIG);
    setMetasploitConfig(DEFAULT_METASPLOIT_CONFIG);
    setSemgrepConfig(DEFAULT_SEMGREP_CONFIG);
    setHasChanges(true);
  };

  const handleResetAgents = () => {
    setAgentsConfig(DEFAULT_AGENTS_CONFIG);
    setHasChanges(true);
  };

  const toggleNucleiTemplate = (template: string) => {
    setNucleiConfig(prev => ({
      ...prev,
      templates: prev.templates.includes(template)
        ? prev.templates.filter(t => t !== template)
        : [...prev.templates, template],
    }));
    setHasChanges(true);
  };

  const toggleSemgrepRuleset = (ruleset: string) => {
    setSemgrepConfig(prev => ({
      ...prev,
      rulesets: prev.rulesets.includes(ruleset)
        ? prev.rulesets.filter(r => r !== ruleset)
        : [...prev.rulesets, ruleset],
    }));
    setHasChanges(true);
  };

  const updateAgentConfig = (agent: keyof AgentsConfig, field: keyof AgentConfig, value: unknown) => {
    setAgentsConfig(prev => ({
      ...prev,
      [agent]: {
        ...prev[agent],
        [field]: value,
      },
    }));
    setHasChanges(true);
  };

  const isLoading = toolsLoading || agentsLoading;

  if (isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-96" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => router.push('/config')}
            className="mb-2 -ml-2"
          >
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back to Configuration
          </Button>
          <h1 className="text-3xl font-bold">Tools & Agents</h1>
          <p className="text-muted-foreground">
            Configure security tool parameters and agent behavior
          </p>
        </div>
        {hasChanges && (
          <Badge variant="outline" className="bg-yellow-500/10 text-yellow-600 border-yellow-500">
            Unsaved changes
          </Badge>
        )}
      </div>

      <Tabs defaultValue="recon">
        <TabsList className="grid w-full grid-cols-6">
          <TabsTrigger value="recon" className="flex items-center gap-1">
            <Search className="h-4 w-4" />
            <span className="hidden sm:inline">Recon</span>
          </TabsTrigger>
          <TabsTrigger value="vuln" className="flex items-center gap-1">
            <Radar className="h-4 w-4" />
            <span className="hidden sm:inline">Vuln Scan</span>
          </TabsTrigger>
          <TabsTrigger value="webapp" className="flex items-center gap-1">
            <Globe className="h-4 w-4" />
            <span className="hidden sm:inline">Web App</span>
          </TabsTrigger>
          <TabsTrigger value="exploit" className="flex items-center gap-1">
            <Shield className="h-4 w-4" />
            <span className="hidden sm:inline">Exploit</span>
          </TabsTrigger>
          <TabsTrigger value="code" className="flex items-center gap-1">
            <Code className="h-4 w-4" />
            <span className="hidden sm:inline">Code Scan</span>
          </TabsTrigger>
          <TabsTrigger value="agents" className="flex items-center gap-1">
            <Users className="h-4 w-4" />
            <span className="hidden sm:inline">Agents</span>
          </TabsTrigger>
        </TabsList>

        {/* RECON TOOLS */}
        <TabsContent value="recon" className="space-y-6 mt-6">
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Terminal className="h-5 w-5 text-primary" />
                <CardTitle>Nmap Configuration</CardTitle>
              </div>
              <CardDescription>
                Port scanning and service detection settings
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Default Ports */}
              <div className="space-y-2">
                <Label htmlFor="nmap-ports">Default Port Range</Label>
                <Input
                  id="nmap-ports"
                  value={nmapConfig.default_ports}
                  onChange={(e) => {
                    setNmapConfig(prev => ({ ...prev, default_ports: e.target.value }));
                    setHasChanges(true);
                  }}
                  placeholder="1-1000 or 22,80,443,8080"
                />
                <p className="text-xs text-muted-foreground">
                  Ports to scan by default. Use ranges (1-1000) or comma-separated (22,80,443).
                </p>
              </div>

              {/* Timing Template */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label>Timing Template (T{nmapConfig.timing_template})</Label>
                  <Badge variant="outline">
                    {nmapConfig.timing_template <= 2 ? 'Slow/Stealthy' :
                     nmapConfig.timing_template === 3 ? 'Normal' :
                     nmapConfig.timing_template === 4 ? 'Aggressive' : 'Insane'}
                  </Badge>
                </div>
                <Slider
                  value={[nmapConfig.timing_template]}
                  onValueChange={(v) => {
                    setNmapConfig(prev => ({ ...prev, timing_template: v[0] as 1|2|3|4|5 }));
                    setHasChanges(true);
                  }}
                  min={1}
                  max={5}
                  step={1}
                  className="w-full"
                />
                <div className="flex justify-between text-xs text-muted-foreground">
                  <span>T1 (Paranoid)</span>
                  <span>T3 (Normal)</span>
                  <span>T5 (Insane)</span>
                </div>
              </div>

              {/* Max Rate */}
              <div className="space-y-2">
                <Label htmlFor="nmap-rate">Max Packet Rate</Label>
                <div className="flex items-center gap-2">
                  <Input
                    id="nmap-rate"
                    type="number"
                    value={nmapConfig.max_rate}
                    onChange={(e) => {
                      setNmapConfig(prev => ({ ...prev, max_rate: parseInt(e.target.value) || 1000 }));
                      setHasChanges(true);
                    }}
                    className="w-32"
                  />
                  <span className="text-sm text-muted-foreground">packets/sec</span>
                </div>
              </div>
            </CardContent>
          </Card>

          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={handleResetTools}>
              <RotateCcw className="h-4 w-4 mr-2" />
              Reset to Defaults
            </Button>
            <Button onClick={handleSaveTools} disabled={saveToolsMutation.isPending}>
              <Save className="h-4 w-4 mr-2" />
              {saveToolsMutation.isPending ? 'Saving...' : 'Save Changes'}
            </Button>
          </div>
        </TabsContent>

        {/* VULN SCANNING */}
        <TabsContent value="vuln" className="space-y-6 mt-6">
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Zap className="h-5 w-5 text-purple-500" />
                <CardTitle>Nuclei Configuration</CardTitle>
              </div>
              <CardDescription>
                Vulnerability scanner template and performance settings
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Templates */}
              <div className="space-y-2">
                <Label>Active Templates</Label>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                  {NUCLEI_TEMPLATE_OPTIONS.map((template) => (
                    <div
                      key={template.value}
                      onClick={() => toggleNucleiTemplate(template.value)}
                      className={`flex items-center space-x-2 p-3 rounded-lg border cursor-pointer transition-colors ${
                        nucleiConfig.templates.includes(template.value)
                          ? 'border-primary bg-primary/5'
                          : 'hover:bg-muted/50'
                      }`}
                    >
                      <Checkbox
                        checked={nucleiConfig.templates.includes(template.value)}
                        onCheckedChange={() => toggleNucleiTemplate(template.value)}
                      />
                      <div>
                        <div className="text-sm font-medium">{template.label}</div>
                        <div className="text-xs text-muted-foreground">{template.description}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Severity Filter */}
              <div className="space-y-2">
                <Label>Severity Filter</Label>
                <Select
                  value={nucleiConfig.severity}
                  onValueChange={(v) => {
                    setNucleiConfig(prev => ({ ...prev, severity: v }));
                    setHasChanges(true);
                  }}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="info,low,medium,high,critical">All Severities</SelectItem>
                    <SelectItem value="low,medium,high,critical">Low and above</SelectItem>
                    <SelectItem value="medium,high,critical">Medium and above</SelectItem>
                    <SelectItem value="high,critical">High and Critical only</SelectItem>
                    <SelectItem value="critical">Critical only</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {/* Performance Settings */}
              <div className="grid md:grid-cols-3 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="nuclei-rate">Rate Limit</Label>
                  <div className="flex items-center gap-2">
                    <Input
                      id="nuclei-rate"
                      type="number"
                      value={nucleiConfig.rate_limit}
                      onChange={(e) => {
                        setNucleiConfig(prev => ({ ...prev, rate_limit: parseInt(e.target.value) || 150 }));
                        setHasChanges(true);
                      }}
                      className="w-24"
                    />
                    <span className="text-xs text-muted-foreground">req/s</span>
                  </div>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="nuclei-bulk">Bulk Size</Label>
                  <Input
                    id="nuclei-bulk"
                    type="number"
                    value={nucleiConfig.bulk_size}
                    onChange={(e) => {
                      setNucleiConfig(prev => ({ ...prev, bulk_size: parseInt(e.target.value) || 25 }));
                      setHasChanges(true);
                    }}
                    className="w-24"
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="nuclei-concurrency">Concurrency</Label>
                  <Input
                    id="nuclei-concurrency"
                    type="number"
                    value={nucleiConfig.concurrency}
                    onChange={(e) => {
                      setNucleiConfig(prev => ({ ...prev, concurrency: parseInt(e.target.value) || 25 }));
                      setHasChanges(true);
                    }}
                    className="w-24"
                  />
                </div>
              </div>

              {/* Custom Templates Path */}
              <div className="space-y-2">
                <Label htmlFor="nuclei-custom">Custom Templates Path (optional)</Label>
                <Input
                  id="nuclei-custom"
                  value={nucleiConfig.custom_templates_path || ''}
                  onChange={(e) => {
                    setNucleiConfig(prev => ({ ...prev, custom_templates_path: e.target.value }));
                    setHasChanges(true);
                  }}
                  placeholder="/path/to/custom/templates"
                />
              </div>
            </CardContent>
          </Card>

          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={handleResetTools}>
              <RotateCcw className="h-4 w-4 mr-2" />
              Reset to Defaults
            </Button>
            <Button onClick={handleSaveTools} disabled={saveToolsMutation.isPending}>
              <Save className="h-4 w-4 mr-2" />
              {saveToolsMutation.isPending ? 'Saving...' : 'Save Changes'}
            </Button>
          </div>
        </TabsContent>

        {/* WEB APP TESTING */}
        <TabsContent value="webapp" className="space-y-6 mt-6">
          {/* SQLMap */}
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Bug className="h-5 w-5 text-red-500" />
                <CardTitle>SQLMap Configuration</CardTitle>
              </div>
              <CardDescription>
                SQL injection testing parameters
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid md:grid-cols-2 gap-6">
                {/* Level */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <Label>Test Level ({sqlmapConfig.level})</Label>
                    <Badge variant="outline">
                      {sqlmapConfig.level <= 2 ? 'Basic' :
                       sqlmapConfig.level === 3 ? 'Medium' : 'Thorough'}
                    </Badge>
                  </div>
                  <Slider
                    value={[sqlmapConfig.level]}
                    onValueChange={(v) => {
                      setSqlmapConfig(prev => ({ ...prev, level: v[0] as 1|2|3|4|5 }));
                      setHasChanges(true);
                    }}
                    min={1}
                    max={5}
                    step={1}
                  />
                  <p className="text-xs text-muted-foreground">
                    Higher levels test more injection points but take longer
                  </p>
                </div>

                {/* Risk */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <Label>Risk Level ({sqlmapConfig.risk})</Label>
                    <Badge variant={sqlmapConfig.risk >= 3 ? 'destructive' : 'outline'}>
                      {sqlmapConfig.risk === 1 ? 'Safe' :
                       sqlmapConfig.risk === 2 ? 'Moderate' : 'Risky'}
                    </Badge>
                  </div>
                  <Slider
                    value={[sqlmapConfig.risk]}
                    onValueChange={(v) => {
                      setSqlmapConfig(prev => ({ ...prev, risk: v[0] as 1|2|3 }));
                      setHasChanges(true);
                    }}
                    min={1}
                    max={3}
                    step={1}
                  />
                  <p className="text-xs text-muted-foreground">
                    Higher risk may cause data modification. Keep at 1-2 for safety.
                  </p>
                </div>
              </div>

              {/* Technique */}
              <div className="space-y-2">
                <Label>Injection Techniques</Label>
                <div className="flex flex-wrap gap-2">
                  {[
                    { key: 'B', name: 'Boolean-based blind' },
                    { key: 'E', name: 'Error-based' },
                    { key: 'U', name: 'Union query-based' },
                    { key: 'S', name: 'Stacked queries' },
                    { key: 'T', name: 'Time-based blind' },
                    { key: 'Q', name: 'Inline queries' },
                  ].map((tech) => (
                    <Badge
                      key={tech.key}
                      variant={sqlmapConfig.technique.includes(tech.key) ? 'default' : 'outline'}
                      className="cursor-pointer"
                      onClick={() => {
                        setSqlmapConfig(prev => ({
                          ...prev,
                          technique: prev.technique.includes(tech.key)
                            ? prev.technique.replace(tech.key, '')
                            : prev.technique + tech.key,
                        }));
                        setHasChanges(true);
                      }}
                    >
                      {tech.key}: {tech.name}
                    </Badge>
                  ))}
                </div>
              </div>

              {/* Threads */}
              <div className="space-y-2">
                <Label htmlFor="sqlmap-threads">Threads</Label>
                <Input
                  id="sqlmap-threads"
                  type="number"
                  value={sqlmapConfig.threads}
                  onChange={(e) => {
                    setSqlmapConfig(prev => ({ ...prev, threads: parseInt(e.target.value) || 4 }));
                    setHasChanges(true);
                  }}
                  className="w-24"
                  min={1}
                  max={10}
                />
              </div>
            </CardContent>
          </Card>

          {/* FFUF */}
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <FileSearch className="h-5 w-5 text-orange-500" />
                <CardTitle>FFUF Configuration</CardTitle>
              </div>
              <CardDescription>
                Directory and endpoint fuzzing settings
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="ffuf-wordlist">Default Wordlist</Label>
                <Input
                  id="ffuf-wordlist"
                  value={ffufConfig.wordlist}
                  onChange={(e) => {
                    setFfufConfig(prev => ({ ...prev, wordlist: e.target.value }));
                    setHasChanges(true);
                  }}
                  placeholder="/opt/pentest/wordlists/common.txt"
                />
              </div>
              <div className="grid md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="ffuf-rate">Request Rate</Label>
                  <div className="flex items-center gap-2">
                    <Input
                      id="ffuf-rate"
                      type="number"
                      value={ffufConfig.rate}
                      onChange={(e) => {
                        setFfufConfig(prev => ({ ...prev, rate: parseInt(e.target.value) || 100 }));
                        setHasChanges(true);
                      }}
                      className="w-24"
                    />
                    <span className="text-xs text-muted-foreground">req/s</span>
                  </div>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="ffuf-timeout">Timeout</Label>
                  <div className="flex items-center gap-2">
                    <Input
                      id="ffuf-timeout"
                      type="number"
                      value={ffufConfig.timeout}
                      onChange={(e) => {
                        setFfufConfig(prev => ({ ...prev, timeout: parseInt(e.target.value) || 10 }));
                        setHasChanges(true);
                      }}
                      className="w-24"
                    />
                    <span className="text-xs text-muted-foreground">seconds</span>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>

          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={handleResetTools}>
              <RotateCcw className="h-4 w-4 mr-2" />
              Reset to Defaults
            </Button>
            <Button onClick={handleSaveTools} disabled={saveToolsMutation.isPending}>
              <Save className="h-4 w-4 mr-2" />
              {saveToolsMutation.isPending ? 'Saving...' : 'Save Changes'}
            </Button>
          </div>
        </TabsContent>

        {/* EXPLOIT */}
        <TabsContent value="exploit" className="space-y-6 mt-6">
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Shield className="h-5 w-5 text-red-500" />
                <CardTitle>Metasploit Configuration</CardTitle>
              </div>
              <CardDescription>
                Exploitation and validation settings
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Check Mode */}
              <div className="flex items-center justify-between p-4 rounded-lg border">
                <div className="space-y-1">
                  <Label>Check Mode Only</Label>
                  <p className="text-sm text-muted-foreground">
                    Only verify vulnerabilities without exploitation
                  </p>
                </div>
                <Switch
                  checked={metasploitConfig.check_mode}
                  onCheckedChange={(checked) => {
                    setMetasploitConfig(prev => ({ ...prev, check_mode: checked }));
                    setHasChanges(true);
                  }}
                />
              </div>

              {!metasploitConfig.check_mode && (
                <div className="p-4 rounded-lg border border-red-500 bg-red-500/10">
                  <div className="flex items-start gap-2">
                    <Info className="h-5 w-5 text-red-500 mt-0.5" />
                    <div className="text-sm text-red-700 dark:text-red-300">
                      <strong>Warning:</strong> Disabling check mode allows actual exploitation.
                      This may cause service disruption or data modification on target systems.
                      Only disable for authorized testing.
                    </div>
                  </div>
                </div>
              )}

              {/* Threads */}
              <div className="space-y-2">
                <Label htmlFor="msf-threads">Threads</Label>
                <Input
                  id="msf-threads"
                  type="number"
                  value={metasploitConfig.threads}
                  onChange={(e) => {
                    setMetasploitConfig(prev => ({ ...prev, threads: parseInt(e.target.value) || 4 }));
                    setHasChanges(true);
                  }}
                  className="w-24"
                  min={1}
                  max={10}
                />
              </div>
            </CardContent>
          </Card>

          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={handleResetTools}>
              <RotateCcw className="h-4 w-4 mr-2" />
              Reset to Defaults
            </Button>
            <Button onClick={handleSaveTools} disabled={saveToolsMutation.isPending}>
              <Save className="h-4 w-4 mr-2" />
              {saveToolsMutation.isPending ? 'Saving...' : 'Save Changes'}
            </Button>
          </div>
        </TabsContent>

        {/* CODE SCANNING */}
        <TabsContent value="code" className="space-y-6 mt-6">
          <Card>
            <CardHeader>
              <div className="flex items-center gap-2">
                <Code className="h-5 w-5 text-green-500" />
                <CardTitle>Semgrep Configuration</CardTitle>
              </div>
              <CardDescription>
                Static analysis rule sets and settings
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Rulesets */}
              <div className="space-y-2">
                <Label>Active Rule Sets</Label>
                <div className="grid grid-cols-2 gap-2">
                  {SEMGREP_RULESET_OPTIONS.map((ruleset) => (
                    <div
                      key={ruleset.value}
                      onClick={() => toggleSemgrepRuleset(ruleset.value)}
                      className={`flex items-center space-x-2 p-3 rounded-lg border cursor-pointer transition-colors ${
                        semgrepConfig.rulesets.includes(ruleset.value)
                          ? 'border-primary bg-primary/5'
                          : 'hover:bg-muted/50'
                      }`}
                    >
                      <Checkbox
                        checked={semgrepConfig.rulesets.includes(ruleset.value)}
                        onCheckedChange={() => toggleSemgrepRuleset(ruleset.value)}
                      />
                      <div>
                        <div className="text-sm font-medium">{ruleset.label}</div>
                        <div className="text-xs text-muted-foreground">{ruleset.description}</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Severity */}
              <div className="space-y-2">
                <Label>Minimum Severity</Label>
                <Select
                  value={semgrepConfig.severity}
                  onValueChange={(v) => {
                    setSemgrepConfig(prev => ({ ...prev, severity: v }));
                    setHasChanges(true);
                  }}
                >
                  <SelectTrigger className="w-48">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="info">Info and above</SelectItem>
                    <SelectItem value="warning">Warning and above</SelectItem>
                    <SelectItem value="error">Error only</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {/* Timeout */}
              <div className="space-y-2">
                <Label htmlFor="semgrep-timeout">Scan Timeout</Label>
                <div className="flex items-center gap-2">
                  <Input
                    id="semgrep-timeout"
                    type="number"
                    value={semgrepConfig.timeout}
                    onChange={(e) => {
                      setSemgrepConfig(prev => ({ ...prev, timeout: parseInt(e.target.value) || 300 }));
                      setHasChanges(true);
                    }}
                    className="w-24"
                  />
                  <span className="text-xs text-muted-foreground">seconds</span>
                </div>
              </div>
            </CardContent>
          </Card>

          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={handleResetTools}>
              <RotateCcw className="h-4 w-4 mr-2" />
              Reset to Defaults
            </Button>
            <Button onClick={handleSaveTools} disabled={saveToolsMutation.isPending}>
              <Save className="h-4 w-4 mr-2" />
              {saveToolsMutation.isPending ? 'Saving...' : 'Save Changes'}
            </Button>
          </div>
        </TabsContent>

        {/* AGENTS */}
        <TabsContent value="agents" className="space-y-6 mt-6">
          <Card>
            <CardHeader>
              <CardTitle>Agent Configuration</CardTitle>
              <CardDescription>
                Configure AI agent behavior and permissions
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {Object.entries(agentsConfig).map(([agentKey, config]) => (
                  <div key={agentKey} className="p-4 rounded-lg border space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div className={`p-2 rounded-lg ${config.enabled ? 'bg-primary/10' : 'bg-muted'}`}>
                          {agentKey === 'recon' && <Search className="h-4 w-4" />}
                          {agentKey === 'vuln-scan' && <Radar className="h-4 w-4" />}
                          {agentKey === 'web-app' && <Globe className="h-4 w-4" />}
                          {agentKey === 'exploit' && <Shield className="h-4 w-4" />}
                          {agentKey === 'security-scan' && <Code className="h-4 w-4" />}
                          {agentKey === 'report' && <Wrench className="h-4 w-4" />}
                        </div>
                        <div>
                          <h3 className="font-medium capitalize">{agentKey.replace('-', ' ')} Agent</h3>
                          <p className="text-sm text-muted-foreground">
                            {agentKey === 'recon' && 'Discovers hosts, ports, and services'}
                            {agentKey === 'vuln-scan' && 'Runs vulnerability scanners'}
                            {agentKey === 'web-app' && 'Tests web application security'}
                            {agentKey === 'exploit' && 'Validates exploitability'}
                            {agentKey === 'security-scan' && 'Scans code for vulnerabilities'}
                            {agentKey === 'report' && 'Generates reports and tickets'}
                          </p>
                        </div>
                      </div>
                      <Switch
                        checked={config.enabled}
                        onCheckedChange={(checked) =>
                          updateAgentConfig(agentKey as keyof AgentsConfig, 'enabled', checked)
                        }
                      />
                    </div>

                    {config.enabled && (
                      <div className="grid md:grid-cols-3 gap-4 pt-2">
                        <div className="space-y-2">
                          <Label className="text-xs">Timeout (minutes)</Label>
                          <Input
                            type="number"
                            value={config.timeout_minutes}
                            onChange={(e) =>
                              updateAgentConfig(
                                agentKey as keyof AgentsConfig,
                                'timeout_minutes',
                                parseInt(e.target.value) || 30
                              )
                            }
                            className="h-8"
                            min={5}
                            max={120}
                          />
                        </div>
                        <div className="flex items-center space-x-2">
                          <Checkbox
                            id={`${agentKey}-auto`}
                            checked={config.auto_start}
                            onCheckedChange={(checked) =>
                              updateAgentConfig(agentKey as keyof AgentsConfig, 'auto_start', checked)
                            }
                          />
                          <Label htmlFor={`${agentKey}-auto`} className="text-xs cursor-pointer">
                            Auto-start in workflow
                          </Label>
                        </div>
                        <div className="flex items-center space-x-2">
                          <Checkbox
                            id={`${agentKey}-approval`}
                            checked={config.requires_approval}
                            onCheckedChange={(checked) =>
                              updateAgentConfig(agentKey as keyof AgentsConfig, 'requires_approval', checked)
                            }
                          />
                          <Label htmlFor={`${agentKey}-approval`} className="text-xs cursor-pointer">
                            Requires approval
                          </Label>
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={handleResetAgents}>
              <RotateCcw className="h-4 w-4 mr-2" />
              Reset to Defaults
            </Button>
            <Button onClick={handleSaveAgents} disabled={saveAgentsMutation.isPending}>
              <Save className="h-4 w-4 mr-2" />
              {saveAgentsMutation.isPending ? 'Saving...' : 'Save Changes'}
            </Button>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
