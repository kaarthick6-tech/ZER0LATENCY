(function () {
    const API_URL = "http://127.0.0.1:8001/analyze-screenshot";

    function createScanner() {
        const form = document.getElementById("scamCheckForm");
        if (!form || document.getElementById("screenshotScannerCard")) return;

        const card = document.createElement("div");
        card.id = "screenshotScannerCard";
        card.className = "stat-card";
        card.style.marginTop = "1rem";
        card.innerHTML = `
            <h3>📸 Screenshot Scanner (WhatsApp / SMS / Invoice)</h3>
            <input id="screenshotInput" type="file" accept="image/*">
            <img id="screenshotPreview" alt="Screenshot preview" style="display:none;max-width:100%;margin-top:0.75rem;border-radius:8px;">
            <button type="button" id="analyzeScreenshotBtn" class="analyze-btn" style="margin-top:0.75rem;">Analyze Screenshot</button>
            <p id="screenshotStatus" style="display:none;margin-top:0.5rem;"></p>
        `;
        form.appendChild(card);

        const input = card.querySelector("#screenshotInput");
        const preview = card.querySelector("#screenshotPreview");
        input.addEventListener("change", function () {
            const file = input.files && input.files[0];
            if (!file) {
                preview.style.display = "none";
                return;
            }
            if (!file.type.startsWith("image/")) {
                input.value = "";
                alert("Please choose an image file.");
                return;
            }
            preview.src = URL.createObjectURL(file);
            preview.style.display = "block";
        });
        card.querySelector("#analyzeScreenshotBtn").addEventListener("click", analyzeScreenshot);
    }

    function setStatus(message, visible) {
        const status = document.getElementById("screenshotStatus");
        if (status) {
            status.textContent = message;
            status.style.display = visible ? "block" : "none";
        }
    }

    function readAsBase64(file) {
        return new Promise(function (resolve, reject) {
            const reader = new FileReader();
            reader.onload = function () { resolve(reader.result); };
            reader.onerror = function () { reject(new Error("Unable to read the image.")); };
            reader.readAsDataURL(file);
        });
    }

    function renderResult(data) {
        const score = Math.min(100, Math.max(0, Number(data.risk_score) || 0));
        const resultSection = document.getElementById("resultsSection");
        const scoreValue = document.getElementById("riskScoreValue");
        const level = document.getElementById("riskLevel");
        const verdict = document.getElementById("verdict");
        const flags = document.getElementById("redFlagsList");
        const recommendations = document.getElementById("recommendationsList");
        if (scoreValue) scoreValue.textContent = String(Math.round(score));
        if (level) level.textContent = data.risk_level || "UNVERIFIABLE";
        if (verdict) verdict.textContent = data.verdict || "No verdict returned.";
        if (flags) {
            flags.innerHTML = "";
            (data.red_flags || []).forEach(function (flag) {
                const item = document.createElement("li");
                item.textContent = flag;
                flags.appendChild(item);
            });
        }
        if (recommendations) {
            recommendations.innerHTML = "";
            (data.recommendations || []).forEach(function (recommendation) {
                const item = document.createElement("li");
                item.textContent = recommendation;
                recommendations.appendChild(item);
            });
        }

        let extractedCard = document.getElementById("screenshotExtractedTextCard");
        if (!extractedCard) {
            extractedCard = document.createElement("div");
            extractedCard.id = "screenshotExtractedTextCard";
            extractedCard.className = "stat-card";
            resultSection.querySelector(".container").appendChild(extractedCard);
        }
        extractedCard.innerHTML = "<h3>📝 Extracted Screenshot Text</h3>";
        const text = document.createElement("pre");
        text.style.whiteSpace = "pre-wrap";
        text.textContent = data.extracted_text || "No readable text was found.";
        extractedCard.appendChild(text);
        if (resultSection) {
            resultSection.style.display = "block";
            resultSection.scrollIntoView({ behavior: "smooth" });
        }
    }

    async function analyzeScreenshot() {
        const input = document.getElementById("screenshotInput");
        const file = input && input.files && input.files[0];
        if (!file) {
            alert("Please choose a screenshot first.");
            return;
        }
        if (file.size > 5 * 1024 * 1024) {
            alert("Screenshot is too large. Please upload an image under 5MB.");
            return;
        }
        setStatus("Analyzing screenshot...", true);
        try {
            const imageBase64 = await readAsBase64(file);
            const modeElement = document.getElementById("analysisMode");
            const response = await fetch(API_URL, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    image_base64: imageBase64,
                    mode: modeElement ? modeElement.value : "b2c"
                })
            });
            const data = await response.json();
            if (!response.ok) throw new Error(data.detail || "Screenshot analysis failed.");
            renderResult(data);
            setStatus("Screenshot analyzed.", true);
        } catch (error) {
            console.error("Screenshot analysis error:", error);
            setStatus("", false);
            alert("Screenshot analysis failed: " + error.message);
        }
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", createScanner);
    } else {
        createScanner();
    }
})();
