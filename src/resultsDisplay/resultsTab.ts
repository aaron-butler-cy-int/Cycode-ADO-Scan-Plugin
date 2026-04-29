import * as SDK from 'azure-devops-extension-sdk';
import { Build } from 'azure-devops-extension-api/Build/Build';

const ATTACHMENT_TYPE = "cycode.scan.result";
const API_VERSION = "7.1";
const LOG = (msg: string, ...args: unknown[]) => console.log(`[Cycode] ${msg}`, ...args);

interface Attachment {
    _links?: { self?: { href?: string } };
}

// Extract timelineId, recordId, and name from the attachment self-link URL.
// Format: .../_apis/build/builds/{buildId}/{timelineId}/{recordId}/attachments/{type}/{name}
function parseAttachmentHref(href: string): { timelineId: string; recordId: string; name: string } | null {
    const match = href.match(/\/builds\/\d+\/([0-9a-f-]+)\/([0-9a-f-]+)\/attachments\/[^/]+\/([^?]+)/i);
    if (!match) {
        LOG('parseAttachmentHref: no match for href:', href);
        return null;
    }
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
    LOG('loadScanResults() called, build.id:', build?.id);
    const base = getBaseUri();
    const project = SDK.getWebContext().project.id;
    LOG('base:', base, 'project:', project);

    const wrapper = document.getElementById("wrapper")!;

    try {
        const token = await SDK.getAccessToken();
        const headers = { Authorization: `Bearer ${token}` };

        const listUrl = `${base}/${project}/_apis/build/builds/${build.id}/attachments/${ATTACHMENT_TYPE}?api-version=${API_VERSION}`;
        LOG('GET', listUrl);
        const listResp = await fetch(listUrl, { headers });
        LOG('attachments response status:', listResp.status);
        if (!listResp.ok) throw new Error(`getAttachments HTTP ${listResp.status}: ${await listResp.text()}`);

        const body = await listResp.json() as { value?: Attachment[] };
        const attachments: Attachment[] = body.value ?? [];
        LOG('attachments count:', attachments.length, attachments);

        if (attachments.length === 0) {
            LOG('no attachments found');
            const p = document.createElement("p");
            p.style.cssText = "color:#546e7a;padding:24px";
            p.textContent = "No Cycode scan results found for this build.";
            wrapper.replaceChildren(p);
            return;
        }

        for (const attachment of attachments) {
            const href = attachment._links?.self?.href;
            LOG('attachment href:', href);
            if (!href) continue;

            const parsed = parseAttachmentHref(href);
            LOG('parsed:', parsed);
            if (!parsed) continue;

            const contentUrl = `${base}/${project}/_apis/build/builds/${build.id}/${parsed.timelineId}/${parsed.recordId}/attachments/${ATTACHMENT_TYPE}/${parsed.name}?api-version=${API_VERSION}`;
            LOG('GET', contentUrl);
            const contentResp = await fetch(contentUrl, { headers });
            LOG('content response status:', contentResp.status);
            if (!contentResp.ok) throw new Error(`getAttachment HTTP ${contentResp.status}: ${await contentResp.text()}`);

            const html = await contentResp.text();
            LOG('content length:', html.length);

            const iframe = document.createElement("iframe");
            iframe.setAttribute("sandbox", "allow-scripts");
            iframe.style.cssText = "width:100%;height:100vh;border:none;display:block";
            iframe.srcdoc = html;
            wrapper.replaceChildren(iframe);
        }
    } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err);
        LOG('ERROR in loadScanResults:', msg, err);
        const p = document.createElement("p");
        p.style.cssText = "color:#c62828;padding:24px";
        p.textContent = `Failed to load Cycode scan results: ${msg}`;
        wrapper.replaceChildren(p);
    }
}

async function initialize(): Promise<void> {
    LOG('initialize() called');
    await SDK.init();
    LOG('SDK.init() complete');

    // For build results tabs ADO passes onBuildChanged as a function in the
    // configuration — call it with our callback rather than using SDK.register.
    const config = SDK.getConfiguration();
    LOG('getConfiguration():', config);

    if (typeof config.onBuildChanged === 'function') {
        LOG('registering via config.onBuildChanged');
        config.onBuildChanged((build: Build) => {
            LOG('onBuildChanged fired, build.id:', build?.id);
            loadScanResults(build);
        });
    } else {
        LOG('WARNING: config.onBuildChanged is not a function:', typeof config.onBuildChanged);
    }

    SDK.notifyLoadSucceeded();
    LOG('notifyLoadSucceeded() called');
}

initialize();
