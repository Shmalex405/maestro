import nodemailer from "nodemailer";

interface EmailConfig {
  host: string;
  port: number;
  secure: boolean;
  user: string;
  pass: string;
  from: string;
}

function getEmailConfig(): EmailConfig {
  return {
    host: process.env.SMTP_HOST || "smtp.gmail.com",
    port: parseInt(process.env.SMTP_PORT || "587", 10),
    secure: process.env.SMTP_SECURE === "true",
    user: process.env.SMTP_USER || "",
    pass: process.env.SMTP_PASS || "",
    from: process.env.SMTP_FROM || "security@yourcompany.com",
  };
}

export async function sendEmail(
  recipients: string[],
  subject: string,
  body: string,
  attachmentUrl?: string
): Promise<void> {
  const config = getEmailConfig();
  
  if (!config.user || !config.pass) {
    console.log("Email not configured, skipping send");
    console.log(`Would send to: ${recipients.join(", ")}`);
    console.log(`Subject: ${subject}`);
    return;
  }
  
  const transporter = nodemailer.createTransport({
    host: config.host,
    port: config.port,
    secure: config.secure,
    auth: {
      user: config.user,
      pass: config.pass,
    },
  });
  
  const mailOptions: nodemailer.SendMailOptions = {
    from: config.from,
    to: recipients.join(", "),
    subject,
    html: body,
  };
  
  if (attachmentUrl) {
    mailOptions.html += `<p><a href="${attachmentUrl}">View full report in SharePoint</a></p>`;
  }
  
  await transporter.sendMail(mailOptions);
}
