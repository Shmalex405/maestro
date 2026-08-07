/**
 * System API Routes
 */

import { Router, Request, Response } from "express";
import Docker from "dockerode";
import * as fs from "fs";
import * as path from "path";
import * as yaml from "js-yaml";
import { getDatabase } from "../../logging/log-store";

export const systemRouter = Router();

const docker = new Docker();

// Load LLM config to determine provider. Anthropic is the only implemented
// provider — local self-hosted models were removed.
function getLLMConfig(): { provider: string; model?: string } {
  try {
    const configPath = path.join(__dirname, "../../../../config/llm-config.yml");
    const content = fs.readFileSync(configPath, "utf-8");
    const config = yaml.load(content) as any;
    return {
      provider: process.env.LLM_PROVIDER || config?.provider || "anthropic",
      model: process.env.ANTHROPIC_MODEL || config?.anthropic?.model,
    };
  } catch (e) {
    return { provider: "unknown" };
  }
}

// Health check
systemRouter.get("/health", (req: Request, res: Response) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// System status - comprehensive
systemRouter.get("/status", async (req: Request, res: Response) => {
  try {
    // Check database
    let databaseConnected = false;
    try {
      const db = getDatabase();
      if (db) {
        db.prepare("SELECT 1").get();
        databaseConnected = true;
      }
    } catch (e) {
      databaseConnected = false;
    }

    // Check Kali container
    let kaliRunning = false;
    let kaliHealthy = false;
    let dockerAvailable = false;
    try {
      const containers = await docker.listContainers({ all: true });
      dockerAvailable = true;
      const kaliContainer = containers.find(
        (c) =>
          c.Names.some((n) => n.includes("kali")) ||
          c.Image.includes("kali")
      );

      if (kaliContainer) {
        kaliRunning = kaliContainer.State === "running";
        kaliHealthy = kaliContainer.Status?.includes("healthy") || kaliRunning;
      }
    } catch (e) {
      dockerAvailable = false;
    }

    // Check LLM provider
    const llmConfig = getLLMConfig();
    let llmConnected = false;

    if (llmConfig.provider === "anthropic") {
      // For Anthropic, just check if API key is set
      llmConnected = !!process.env.ANTHROPIC_API_KEY;
    }

    // Build response matching SystemStatus interface
    res.json({
      healthy: databaseConnected && kaliRunning && llmConnected,
      mcp_server_connected: true, // We're responding, so yes
      database_connected: databaseConnected,
      docker: {
        available: dockerAvailable,
        kali_running: kaliRunning,
        kali_healthy: kaliHealthy,
      },
      llm_provider: llmConfig.provider,
      llm_connected: llmConnected,
      llm_model: llmConfig.model,
      uptime_seconds: Math.floor(process.uptime()),
      version: "0.1.0",
    });
  } catch (error) {
    console.error("Error getting system status:", error);
    res.status(500).json({ error: "Failed to get system status" });
  }
});

// Available tools
systemRouter.get("/tools", (req: Request, res: Response) => {
  const tools = [
    // Recon
    { name: "scan_ports", category: "recon", description: "Port scanning with nmap" },
    { name: "enumerate_subdomains", category: "recon", description: "Subdomain enumeration" },
    { name: "fingerprint_services", category: "recon", description: "Service fingerprinting" },
    { name: "discover_hosts", category: "recon", description: "Host discovery" },
    { name: "web_technology_scan", category: "recon", description: "Web technology detection" },

    // Vuln Scanner
    { name: "run_nuclei", category: "vuln_scanner", description: "Nuclei vulnerability scanner" },
    { name: "run_nikto", category: "vuln_scanner", description: "Nikto web server scanner" },
    { name: "run_wpscan", category: "vuln_scanner", description: "WordPress vulnerability scanner" },
    { name: "search_exploits", category: "vuln_scanner", description: "Search exploit database" },

    // Web App
    { name: "run_sqlmap", category: "web_app", description: "SQL injection testing" },
    { name: "test_xss", category: "web_app", description: "XSS testing" },
    { name: "fuzz_endpoints", category: "web_app", description: "Directory/endpoint fuzzing" },
    { name: "crawl_site", category: "web_app", description: "Web site crawling" },

    // Exploit
    { name: "run_metasploit", category: "exploit", description: "Metasploit module execution" },
    { name: "validate_cve", category: "exploit", description: "CVE validation" },
    { name: "execute_custom_exploit", category: "exploit", description: "Custom exploit execution" },

    // Code Scan
    { name: "scan_repository", category: "code_scan", description: "Full repository scan" },
    { name: "scan_semgrep", category: "code_scan", description: "Semgrep SAST scan" },
    { name: "scan_bandit", category: "code_scan", description: "Python security scan" },
    { name: "scan_njsscan", category: "code_scan", description: "Node.js security scan" },
    { name: "scan_secrets", category: "code_scan", description: "Secret detection" },
    { name: "scan_dependencies", category: "code_scan", description: "Dependency scanning" },
    { name: "scan_iac", category: "code_scan", description: "Infrastructure as Code scanning" },

    // Reporting
    { name: "create_finding", category: "reporting", description: "Create finding record" },
    { name: "generate_report", category: "reporting", description: "Generate assessment report" },
    { name: "create_jira_ticket", category: "reporting", description: "Create Jira ticket" },
    { name: "upload_report", category: "reporting", description: "Upload report to SharePoint" },
  ];

  res.json(tools);
});

// Docker status - detailed Kali container info
systemRouter.get("/docker", async (req: Request, res: Response) => {
  try {
    const containers = await docker.listContainers({ all: true });
    const kaliContainer = containers.find(
      (c) =>
        c.Names.some((n) => n.includes("kali")) ||
        c.Image.includes("kali")
    );

    if (!kaliContainer) {
      return res.json({
        available: false,
        kali_running: false,
        kali_healthy: false,
        message: "Kali container not found. Run 'docker compose up -d' in the docker directory.",
      });
    }

    const isRunning = kaliContainer.State === "running";
    const isHealthy = kaliContainer.Status?.includes("healthy") || isRunning;

    res.json({
      available: true,
      kali_running: isRunning,
      kali_healthy: isHealthy,
      container_id: kaliContainer.Id.slice(0, 12),
      image: kaliContainer.Image,
      status: kaliContainer.Status,
      created: kaliContainer.Created,
    });
  } catch (error) {
    console.error("Error getting Docker status:", error);
    res.status(500).json({
      available: false,
      kali_running: false,
      kali_healthy: false,
      error: "Failed to connect to Docker. Is Docker running?",
    });
  }
});

// Start Kali container
systemRouter.post("/docker/start", async (req: Request, res: Response) => {
  try {
    // First, find the Kali container
    const containers = await docker.listContainers({ all: true });
    const kaliContainer = containers.find(
      (c) =>
        c.Names.some((n) => n.includes("kali")) ||
        c.Image.includes("kali")
    );

    if (!kaliContainer) {
      return res.status(404).json({
        success: false,
        error: "Kali container not found. Please run 'docker compose up -d' first to create it.",
      });
    }

    if (kaliContainer.State === "running") {
      return res.json({
        success: true,
        message: "Kali container is already running",
        already_running: true,
      });
    }

    // Start the container
    const container = docker.getContainer(kaliContainer.Id);
    await container.start();

    res.json({
      success: true,
      message: "Kali container started successfully",
      container_id: kaliContainer.Id.slice(0, 12),
    });
  } catch (error: any) {
    console.error("Error starting Kali container:", error);
    res.status(500).json({
      success: false,
      error: error.message || "Failed to start Kali container",
    });
  }
});

// Stop Kali container
systemRouter.post("/docker/stop", async (req: Request, res: Response) => {
  try {
    // First, find the Kali container
    const containers = await docker.listContainers({ all: true });
    const kaliContainer = containers.find(
      (c) =>
        c.Names.some((n) => n.includes("kali")) ||
        c.Image.includes("kali")
    );

    if (!kaliContainer) {
      return res.status(404).json({
        success: false,
        error: "Kali container not found",
      });
    }

    if (kaliContainer.State !== "running") {
      return res.json({
        success: true,
        message: "Kali container is already stopped",
        already_stopped: true,
      });
    }

    // Stop the container
    const container = docker.getContainer(kaliContainer.Id);
    await container.stop();

    res.json({
      success: true,
      message: "Kali container stopped successfully",
      container_id: kaliContainer.Id.slice(0, 12),
    });
  } catch (error: any) {
    console.error("Error stopping Kali container:", error);
    res.status(500).json({
      success: false,
      error: error.message || "Failed to stop Kali container",
    });
  }
});
