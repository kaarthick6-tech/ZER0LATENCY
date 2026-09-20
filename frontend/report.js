(function () {
    const analyzeButton = document.getElementById("analyzeBtn");
    const resultsSection = document.getElementById("resultsSection");
    let reportButtonsInjected = false;

    function getReportData() {
        const company = document.getElementById("companyName");
        const score = document.getElementById("riskScoreValue");
        const verdict = document.getElementById("verdict");
        const flags = document.getElementById("redFlagsList");

        return {
            company: company ? company.value.trim() || "Not provided" : "Not provided",
            score: score ? score.textContent.trim() || "Unknown" : "Unknown",
            verdict: verdict ? verdict.textContent.trim() || "Unknown" : "Unknown",
            flags: flags ? Array.from(flags.querySelectorAll("li"))
                .map(function (item) { return item.textContent.trim(); })
                .filter(Boolean)
                .join("; ") || "None detected" : "None detected"
        };
    }

    function createButton(text, backgroundColor) {
        const button = document.createElement("button");
        button.type = "button";
        button.textContent = text;
        button.style.background = backgroundColor;
        button.style.color = "#fff";
        button.style.border = "none";
        button.style.borderRadius = "8px";
        button.style.padding = "0.75rem 1rem";
        button.style.marginTop = "15px";
        button.style.marginRight = "10px";
        button.style.cursor = "pointer";
        return button;
    }

    function injectReportButtons() {
        if (reportButtonsInjected || !resultsSection || resultsSection.style.display === "none") {
            return;
        }

        const container = resultsSection.querySelector(".container");
        if (!container) return;

        const copyButton = createButton("📄 Copy Risk Report", "#64748b");
        const whatsappButton = createButton("🚨 Warn on WhatsApp", "#25D366");

        copyButton.addEventListener("click", async function () {
            const data = getReportData();
            const report = [
                "SCAMCHECK REPORT",
                `Company: ${data.company}`,
                `Risk: ${data.score}`,
                `Verdict: ${data.verdict}`,
                `Flags: ${data.flags}`
            ].join("\n");

            try {
                await navigator.clipboard.writeText(report);
                copyButton.textContent = "✅ Copied to Clipboard!";
                setTimeout(function () {
                    copyButton.textContent = "📄 Copy Risk Report";
                }, 2000);
            } catch (error) {
                console.error("Unable to copy risk report:", error);
                alert("Unable to copy the report automatically. Please try again.");
            }
        });

        whatsappButton.addEventListener("click", function () {
            const data = getReportData();
            const message = [
                "⚠️ SCAM ALERT from ScamCheck!",
                `Company: ${data.company}`,
                `Risk: ${data.score}`,
                `Verdict: ${data.verdict}`,
                `Flags: ${data.flags}`,
                "Do not pay or send documents!"
            ].join("\n");
            const encodedMessage = encodeURIComponent(message);
            window.open(`https://wa.me/?text=${encodedMessage}`, "_blank", "noopener");
        });

        container.appendChild(copyButton);
        container.appendChild(whatsappButton);
        reportButtonsInjected = true;
    }

    function waitForResults() {
        let attempts = 0;
        const timer = setInterval(function () {
            attempts += 1;
            if (resultsSection && resultsSection.style.display !== "none") {
                clearInterval(timer);
                injectReportButtons();
            } else if (attempts >= 100) {
                clearInterval(timer);
            }
        }, 100);
    }

    if (analyzeButton) {
        analyzeButton.addEventListener("click", waitForResults);
    }
})();
