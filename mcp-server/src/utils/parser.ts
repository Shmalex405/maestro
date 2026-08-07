export function parseNmapOutput(xmlOutput: string): string {
  // Parse nmap XML output into structured JSON
  // This is a simplified parser - consider using a proper XML parser
  const results: any = {
    hosts: [],
    scan_stats: {},
  };

  // Extract host information using regex (simplified)
  const hostMatches = xmlOutput.matchAll(/<host.*?<\/host>/gs);
  
  for (const match of hostMatches) {
    const hostXml = match[0];
    const host: any = {
      address: "",
      ports: [],
    };
    
    // Extract IP
    const addrMatch = hostXml.match(/addr="([^"]+)"/);
    if (addrMatch) {
      host.address = addrMatch[1];
    }
    
    // Extract ports
    const portMatches = hostXml.matchAll(/<port protocol="([^"]+)" portid="(\d+)".*?<state state="([^"]+)".*?<service name="([^"]*)".*?(?:version="([^"]*)")?/gs);
    
    for (const portMatch of portMatches) {
      host.ports.push({
        protocol: portMatch[1],
        port: portMatch[2],
        state: portMatch[3],
        service: portMatch[4],
        version: portMatch[5] || "",
      });
    }
    
    results.hosts.push(host);
  }

  return JSON.stringify(results, null, 2);
}

export function parseSubfinderOutput(subfinderOutput: string, amassOutput: string = ""): string {
  const subdomains = new Set<string>();
  
  // Parse subfinder output (one domain per line)
  subfinderOutput.split("\n").forEach(line => {
    const domain = line.trim();
    if (domain) subdomains.add(domain);
  });
  
  // Parse amass output (one domain per line)
  amassOutput.split("\n").forEach(line => {
    const domain = line.trim();
    if (domain) subdomains.add(domain);
  });

  return JSON.stringify({
    total: subdomains.size,
    subdomains: Array.from(subdomains).sort(),
  }, null, 2);
}
