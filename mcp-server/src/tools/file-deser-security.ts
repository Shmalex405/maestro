import { executeInKali } from "../utils/docker-exec";

export const fileDeserSecurityTools = [
  {
    name: "test_file_upload",
    description: "Test file upload functionality for security vulnerabilities: unrestricted file types (web shells, executables), content-type bypass, extension bypass (double extensions, null bytes), path traversal in filenames, and file size limit enforcement.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "File upload endpoint URL" },
        file_field: { type: "string", description: "Form field name for file upload", default: "file" },
        method: { type: "string", description: "HTTP method", default: "POST" },
        headers: { type: "object", description: "Custom headers (e.g., authentication tokens)" },
        additional_fields: {
          type: "object",
          description: "Additional form fields to include with the upload (e.g., {'description': 'test'})",
        },
        test_types: {
          type: "array",
          items: { type: "string" },
          description: "Specific tests: 'extension_bypass', 'content_type_bypass', 'path_traversal', 'size_limit', 'web_shell'. Defaults to all.",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "test_deserialization",
    description: "Test for insecure deserialization vulnerabilities. Generates and sends crafted serialized payloads for Java (ObjectInputStream), Python (pickle/yaml), PHP (unserialize), Ruby (Marshal), and .NET (BinaryFormatter). NON-DESTRUCTIVE: uses detection payloads only (DNS/sleep-based).",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target URL or endpoint that accepts serialized data" },
        language: {
          type: "string",
          description: "Target language/framework: 'java', 'python', 'php', 'ruby', 'dotnet', 'auto'",
          default: "auto",
        },
        parameter: { type: "string", description: "Parameter or field that accepts serialized data" },
        method: { type: "string", description: "HTTP method", default: "POST" },
        content_type: { type: "string", description: "Content-Type header value" },
        headers: { type: "object", description: "Custom request headers" },
        callback_url: { type: "string", description: "External callback URL for blind deserialization detection (e.g., Burp Collaborator)" },
      },
      required: ["target"],
    },
  },
];

export const fileDeserSecurityHandlers: Record<string, Function> = {
  test_file_upload: async (args: {
    target: string;
    file_field?: string;
    method?: string;
    headers?: Record<string, string>;
    additional_fields?: Record<string, string>;
    test_types?: string[];
  }) => {
    const safeArgs = JSON.stringify(args).replace(/'/g, "'\\''");
    const command = `python3 /opt/pentest/scripts/test-file-upload.py '${safeArgs}'`;
    return await executeInKali(command);
  },

  test_deserialization: async (args: {
    target: string;
    language?: string;
    parameter?: string;
    method?: string;
    content_type?: string;
    headers?: Record<string, string>;
    callback_url?: string;
  }) => {
    const safeArgs = JSON.stringify(args).replace(/'/g, "'\\''");
    const command = `python3 /opt/pentest/scripts/test-deserialization.py '${safeArgs}'`;
    return await executeInKali(command);
  },
};
