import * as SDK from 'azure-devops-extension-sdk';
import { getClient } from 'azure-devops-extension-api';
import { BuildRestClient } from 'azure-devops-extension-api/Build/BuildClient';
import { Build } from 'azure-devops-extension-api/Build/Build';

const ATTACHMENT_TYPE = "cycode.scan.result";

async function loadScanResults(build: Build): Promise<void> {
    const webContext = SDK.getWebContext();
    const buildClient = getClient(BuildRestClient);
    const wrapper = document.getElementById("wrapper")!;

    try {
        const attachments = await buildClient.getAttachments(
            webContext.project.id,
            build.id,
            ATTACHMENT_TYPE
        );

        if (!attachments || attachments.length === 0) {
            const p = document.createElement("p");
            p.style.cssText = "color:#546e7a;padding:24px";
            p.textContent = "No Cycode scan results found for this build.";
            wrapper.replaceChildren(p);
            return;
        }

        // Render each attachment; last one wins (most recent result).
        // The extension runs in an authenticated ADO browser session so fetch()
        // to the _links.self.href URL works without manual auth headers.
        for (const attachment of attachments) {
            const href = attachment._links?.self?.href as string | undefined;
            if (!href) continue;

            const response = await fetch(href);
            if (!response.ok) continue;

            const content = await response.arrayBuffer();

            // Render in a sandboxed iframe so the report's inline styles and
            // filter script run correctly without DOM sanitization.
            const iframe = document.createElement("iframe");
            iframe.setAttribute("sandbox", "allow-scripts");
            iframe.style.cssText = "width:100%;height:100vh;border:none;display:block";
            iframe.srcdoc = new TextDecoder().decode(content);
            wrapper.replaceChildren(iframe);
            document.body.style.overflow = "visible";
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
    SDK.register(SDK.getContributionId(), {
        onBuildChanged: (build: Build): void => {
            loadScanResults(build);
        }
    });
    SDK.notifyLoadSucceeded();
}

initialize();
