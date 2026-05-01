import * as SDK from 'azure-devops-extension-sdk';
import { Build } from 'azure-devops-extension-api/Build/Build';

const ATTACHMENT_TYPE = "cycode.scan.result";
const API_VERSION = "7.1";

interface Attachment {
    _links?: { self?: { href?: string } };
}

// Extract timelineId, recordId, and name from the attachment self-link URL.
// Format: .../_apis/build/builds/{buildId}/{timelineId}/{recordId}/attachments/{type}/{name}
function parseAttachmentHref(href: string): { timelineId: string; recordId: string; name: string } | null {
    const match = href.match(/\/builds\/\d+\/([0-9a-f-]+)\/([0-9a-f-]+)\/attachments\/[^/]+\/([^?]+)/i);
    if (!match) return null;
    return { timelineId: match[1], recordId: match[2], name: match[3] };
}

function getBaseUri(): string {
    // IWebContext types are a subset of the runtime shape — collection.uri
    // exists at runtime in hosted ADO but is not declared in the SDK types.
    const ctx = SDK.getWebContext() as unknown as { collection?: { uri?: string } };
    if (ctx.collection?.uri) return ctx.collection.uri.replace(/\/$/, '');
    const host = SDK.getHost();
    return host.isHosted
        ? `https://dev.azure.com/${host.name}`
        : window.location.origin;
}

async function loadScanResults(build: Build): Promise<void> {
    const base = getBaseUri();
    const project = SDK.getWebContext().project.id;
    const wrapper = document.getElementById("wrapper")!;

    try {
        const token = await SDK.getAccessToken();
        const headers = { Authorization: `Bearer ${token}` };

        const listUrl = `${base}/${project}/_apis/build/builds/${build.id}/attachments/${ATTACHMENT_TYPE}?api-version=${API_VERSION}`;
        const listResp = await fetch(listUrl, { headers });
        if (!listResp.ok) throw new Error(`getAttachments HTTP ${listResp.status}: ${await listResp.text()}`);

        const body = await listResp.json() as { value?: Attachment[] };
        const attachments: Attachment[] = body.value ?? [];

        if (attachments.length === 0) {
            const p = document.createElement("p");
            p.style.cssText = "color:#546e7a;padding:24px";
            p.textContent = "No Cycode scan results found for this build.";
            wrapper.replaceChildren(p);
            return;
        }

        for (const attachment of attachments) {
            const href = attachment._links?.self?.href;
            if (!href) continue;

            const parsed = parseAttachmentHref(href);
            if (!parsed) continue;

            const contentUrl = `${base}/${project}/_apis/build/builds/${build.id}/${parsed.timelineId}/${parsed.recordId}/attachments/${ATTACHMENT_TYPE}/${parsed.name}?api-version=${API_VERSION}`;
            const contentResp = await fetch(contentUrl, { headers });
            if (!contentResp.ok) throw new Error(`getAttachment HTTP ${contentResp.status}: ${await contentResp.text()}`);

            const html = await contentResp.text();
            const iframe = document.createElement("iframe");
            iframe.setAttribute("sandbox", "allow-scripts");
            iframe.style.cssText = "width:100%;height:100vh;border:none;display:block";
            iframe.srcdoc = html;
            wrapper.replaceChildren(iframe);
        }
    } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        const p = document.createElement("p");
        p.style.cssText = "color:#c62828;padding:24px";
        p.textContent = `Failed to load Cycode scan results: ${msg}`;
        wrapper.replaceChildren(p);
    }
}

async function initialize(): Promise<void> {
    await SDK.init();

    // For build results tabs ADO passes onBuildChanged as a function in the
    // configuration — call it with our callback rather than using SDK.register.
    const config = SDK.getConfiguration();

    if (typeof config.onBuildChanged === 'function') {
        config.onBuildChanged((build: Build) => {
            loadScanResults(build);
        });
    }

    SDK.notifyLoadSucceeded();
}

initialize();
