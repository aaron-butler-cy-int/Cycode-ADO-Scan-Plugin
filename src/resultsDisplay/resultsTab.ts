import * as SDK from 'azure-devops-extension-sdk';
import { getClient } from 'azure-devops-extension-api';
import { BuildRestClient } from 'azure-devops-extension-api/Build/BuildClient';
import { Build } from 'azure-devops-extension-api/Build/Build';

const ATTACHMENT_TYPE = "cycode.scan.result";
const LOG = (msg: string, ...args: unknown[]) => console.log(`[Cycode] ${msg}`, ...args);

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

async function loadScanResults(build: Build): Promise<void> {
    LOG('loadScanResults() called, build.id:', build?.id);
    const webContext = SDK.getWebContext();
    LOG('webContext.project.id:', webContext?.project?.id);
    const buildClient = getClient(BuildRestClient);
    const wrapper = document.getElementById("wrapper")!;

    try {
        LOG('calling getAttachments, type:', ATTACHMENT_TYPE);
        const attachments = await buildClient.getAttachments(
            webContext.project.id,
            build.id,
            ATTACHMENT_TYPE
        );
        LOG('getAttachments returned:', attachments?.length, attachments);

        if (!attachments || attachments.length === 0) {
            LOG('no attachments found');
            const p = document.createElement("p");
            p.style.cssText = "color:#546e7a;padding:24px";
            p.textContent = "No Cycode scan results found for this build.";
            wrapper.replaceChildren(p);
            return;
        }

        for (const attachment of attachments) {
            const href = attachment._links?.self?.href as string | undefined;
            LOG('attachment href:', href);
            if (!href) continue;

            const parsed = parseAttachmentHref(href);
            LOG('parsed:', parsed);
            if (!parsed) continue;

            LOG('calling getAttachment:', parsed);
            const content = await buildClient.getAttachment(
                webContext.project.id,
                build.id,
                parsed.timelineId,
                parsed.recordId,
                ATTACHMENT_TYPE,
                parsed.name
            ) as unknown as ArrayBuffer;

            LOG('getAttachment returned, byteLength:', (content as ArrayBuffer)?.byteLength ?? typeof content);
            const iframe = document.createElement("iframe");
            iframe.setAttribute("sandbox", "allow-scripts");
            iframe.style.cssText = "width:100%;height:100vh;border:none;display:block";
            iframe.srcdoc = new TextDecoder().decode(content);
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
    LOG('initialize() called, SDK type:', typeof SDK);
    LOG('SDK keys:', Object.keys(SDK as object));

    await SDK.init();
    LOG('SDK.init() complete');

    const contributionId = SDK.getContributionId();
    LOG('contributionId:', contributionId);

    SDK.register(contributionId, {
        onBuildChanged: (build: Build): void => {
            LOG('onBuildChanged fired, build.id:', build?.id);
            loadScanResults(build);
        }
    });
    LOG('SDK.register() complete');

    SDK.notifyLoadSucceeded();
    LOG('notifyLoadSucceeded() called');

    const config = SDK.getConfiguration();
    LOG('getConfiguration():', config);
    const initialBuild = config.build as Build | undefined;
    LOG('initialBuild from config:', initialBuild?.id ?? 'none');
    if (initialBuild) {
        loadScanResults(initialBuild);
    }
}

initialize();
