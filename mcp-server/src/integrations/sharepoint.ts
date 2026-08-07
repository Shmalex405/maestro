interface SharePointConfig {
  site_url: string;
  client_id: string;
  client_secret: string;
  folder_path: string;
}

function getSharePointConfig(): SharePointConfig {
  return {
    site_url: process.env.SHAREPOINT_SITE_URL || "",
    client_id: process.env.SHAREPOINT_CLIENT_ID || "",
    client_secret: process.env.SHAREPOINT_CLIENT_SECRET || "",
    folder_path: process.env.SHAREPOINT_FOLDER_PATH || "/SecurityReports",
  };
}

export async function uploadToSharePoint(
  content: string,
  filename: string
): Promise<string> {
  const config = getSharePointConfig();
  
  if (!config.site_url || !config.client_id) {
    // Fallback to local storage if SharePoint not configured
    const fs = await import("fs");
    const path = await import("path");
    const localPath = path.join(__dirname, "../../data/reports", filename);
    
    // Ensure directory exists
    const dir = path.dirname(localPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    
    fs.writeFileSync(localPath, content);
    return `file://${localPath}`;
  }
  
  // Get access token
  const tokenResponse = await fetch(
    `https://accounts.accesscontrol.windows.net/${config.site_url}/tokens/OAuth/2`,
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: config.client_id,
        client_secret: config.client_secret,
        resource: `00000003-0000-0ff1-ce00-000000000000/${config.site_url}@${config.site_url}`,
      }),
    }
  );
  
  const tokenData = await tokenResponse.json() as { access_token: string };
  const accessToken = tokenData.access_token;
  
  // Upload file
  const uploadUrl = `${config.site_url}/_api/web/GetFolderByServerRelativeUrl('${config.folder_path}')/Files/add(url='${filename}',overwrite=true)`;
  
  const uploadResponse = await fetch(uploadUrl, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${accessToken}`,
      "Content-Type": "application/octet-stream",
    },
    body: content,
  });
  
  if (!uploadResponse.ok) {
    throw new Error(`SharePoint upload failed: ${await uploadResponse.text()}`);
  }
  
  const result = await uploadResponse.json() as { ServerRelativeUrl: string };
  return result.ServerRelativeUrl;
}
