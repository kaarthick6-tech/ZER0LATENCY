// API endpoint
const API_URL = "http://127.0.0.1:8001/analyze";

// DOM Elements
const analyzeBtn = document.getElementById('analyzeBtn');
const loadingIndicator = document.getElementById('loadingIndicator');
const resultsSection = document.getElementById('resultsSection');
const riskScoreValue = document.getElementById('riskScoreValue');
const riskScoreCircle = document.getElementById('riskScoreCircle');
const riskScoreContainer = document.querySelector('.risk-score-container');
const riskLevel = document.getElementById('riskLevel');
const verdict = document.getElementById('verdict');
const analysisConfidence = document.getElementById('analysisConfidence');
const sosAlertBox = document.getElementById('sosAlertBox');
const sosMessageText = document.getElementById('sosMessageText');
const copySosBtn = document.getElementById('copySosBtn');
const redFlagsCard = document.getElementById('redFlagsCard');
const recommendationsCard = document.getElementById('recommendationsCard');
const guidanceCard = document.getElementById('guidanceCard');
const guidanceReason = document.getElementById('guidanceReason');
const analysisDetailsGrid = document.getElementById('analysisDetailsGrid');
const highlightedTextCard = document.getElementById('highlightedTextCard');
const highlightedText = document.getElementById('highlightedText');

// Analyze button click handler
if (analyzeBtn) {
    analyzeBtn.addEventListener('click', analyzeOpportunity);
}
if (copySosBtn) {
    copySosBtn.addEventListener('click', copySOSMessage);
}

// Analyze opportunity function
async function analyzeOpportunity() {
    // Get form values
    const companyName = document.getElementById('companyName').value.trim();
    const email = document.getElementById('email').value.trim();
    const phone = document.getElementById('phone').value.trim();
    const website = document.getElementById('website').value.trim();
    const jobDescription = document.getElementById('jobDescription').value.trim();
    const salary = document.getElementById('salary').value.trim();

    // Validation
    if (!companyName || !email || !jobDescription) {
        alert('Please fill in all required fields (Company Name, Email, Job Description)');
        return;
    }

    // Show loading
    showLoading();

    // Prepare request data
    const requestData = {
        company_name: companyName,
        email: email,
        phone: phone,
        website: website,
        job_description: jobDescription,
        salary: salary
    };

    try {
        // Send request to backend
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(requestData)
        });

        if (!response.ok) {
            let detail = `HTTP error! status: ${response.status}`;
            try {
                const errorData = await response.json();
                detail = errorData.detail || detail;
            } catch {
                // Keep the HTTP status when the server returns non-JSON data.
            }
            throw new Error(detail);
        }

        const data = await response.json();

        // Hide loading and show results
        hideLoading();
        displayResults(data);

    } catch (error) {
        console.error('Analysis error:', error);
        hideLoading();
        alert(`Analysis failed: ${error.message}`);
    }
}

// Display analysis results
function displayResults(data) {
    const isUnverifiable = data.risk_level === 'UNVERIFIABLE';
    // Update risk score circle
    const riskScore = isUnverifiable
        ? 0
        : Math.min(100, Math.max(0, Number(data.overall_risk_score) || 0));

    console.log('Risk Score:', riskScore); // Debug log

    // Animate score
    if (riskScoreValue && !isUnverifiable) {
        animateValue(riskScoreValue, 0, Math.round(riskScore), 1000);
    } else if (riskScoreValue) {
        riskScoreValue.textContent = '-';
    }

    // Set color based on risk (FIXED)
    let gradientColor;
    let riskText;

    if (isUnverifiable) {
        gradientColor = '#64748b'; // Slate - UNVERIFIABLE
        riskText = 'UNVERIFIABLE';
        if (riskLevel) riskLevel.className = 'risk-level text-slate';
    } else if (riskScore >= 70) {
        gradientColor = '#ef4444'; // Red - HIGH RISK
        riskText = 'HIGH RISK';
        if (riskLevel) riskLevel.className = 'risk-level text-danger';
    } else if (riskScore >= 40) {
        gradientColor = '#f59e0b'; // Orange - MEDIUM RISK
        riskText = 'MEDIUM RISK';
        if (riskLevel) riskLevel.className = 'risk-level text-warning';
    } else {
        gradientColor = '#10b981'; // Green - LOW RISK
        riskText = 'LOW RISK';
        if (riskLevel) riskLevel.className = 'risk-level text-success';
    }

    // Update circle gradient (FIXED - use proper percentage)
    const degrees = (riskScore / 100) * 360;
    if (riskScoreCircle) {
        riskScoreCircle.style.background = `conic-gradient(${gradientColor} ${degrees}deg, var(--border-color) ${degrees}deg)`;
    }

    if (riskLevel) riskLevel.textContent = riskText;
    if (analysisConfidence) {
        const confidence = Math.min(100, Math.max(0, Number(data.confidence) || 0));
        analysisConfidence.textContent = `Analysis Confidence: ${confidence}%`;
    }
    if (verdict) verdict.textContent = data.verdict || 'No verdict returned';

    toggleUnverifiableState(isUnverifiable);
    if (!isUnverifiable) {
        // Display URL analysis
        displayURLAnalysis(data.url_analysis || {});

        // Display content analysis
        displayContentAnalysis(data.content_analysis || {});

        // Display red flags
        displayRedFlags(data.content_analysis || {});

        // Display recommendations
        displayRecommendations(data.recommendations || []);
        displayHighlightedText(data);
    } else {
        const why = data.content_analysis?.input_validity?.reason || 'Insufficient reliable job-offer information.';
        if (guidanceReason) {
            guidanceReason.textContent = `Why: ${why}`;
        }
        displayHighlightedText(null);
        displaySOSAlert(null);
    }

    // Display SOS alert
    if (!isUnverifiable) {
        displaySOSAlert(data.sos_message);
    }

    // Show results section
    if (resultsSection) {
        resultsSection.style.display = 'block';
        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }
}

// Animate value
function animateValue(element, start, end, duration) {
    let startTimestamp = null;
    const step = (timestamp) => {
        if (!startTimestamp) startTimestamp = timestamp;
        const progress = Math.min((timestamp - startTimestamp) / duration, 1);
        element.textContent = Math.floor(progress * (end - start) + start);
        if (progress < 1) {
            window.requestAnimationFrame(step);
        }
    };
    window.requestAnimationFrame(step);
}

// Display URL analysis
function displayURLAnalysis(urlAnalysis) {
    const urlRiskScore = document.getElementById('urlRiskScore');
    const sslStatus = document.getElementById('sslStatus');

    if (urlRiskScore && urlAnalysis.overall_risk_score !== undefined) {
        urlRiskScore.textContent = `${Math.round(urlAnalysis.overall_risk_score)}/100`;
    }

    if (sslStatus && urlAnalysis.has_ssl !== undefined) {
        if (urlAnalysis.has_ssl) {
            sslStatus.innerHTML = '<span style="color: #10b981;">✓ HTTPS Enabled</span>';
        } else {
            sslStatus.innerHTML = '<span style="color: #ef4444;">✗ No HTTPS</span>';
        }
    }
}

// Display content analysis
function displayContentAnalysis(contentAnalysis) {
    const redFlagsCount = document.getElementById('redFlagsCount');
    const emailStatus = document.getElementById('emailStatus');
    const salaryValue = document.getElementById('salaryValue');
    const contentRiskScore = document.getElementById('contentRiskScore');

    if (redFlagsCount && contentAnalysis.keyword_analysis) {
        redFlagsCount.textContent = `${contentAnalysis.keyword_analysis.flag_count} suspicious patterns`;
    }

    if (emailStatus && contentAnalysis.email_analysis) {
        if (contentAnalysis.email_analysis.is_suspicious) {
            emailStatus.innerHTML = '<span style="color: #ef4444;">⚠ Suspicious domain</span>';
        } else {
            emailStatus.innerHTML = '<span style="color: #10b981;">✓ Professional domain</span>';
        }
    }

    if (salaryValue && contentAnalysis.salary_analysis) {
        const salaryInput = document.getElementById('salary');
        salaryValue.textContent = salaryInput?.value.trim() || 'Not provided';
    }

    if (contentRiskScore && contentAnalysis.overall_risk_score !== undefined) {
        contentRiskScore.textContent = `${Math.round(contentAnalysis.overall_risk_score)}/100`;
    }
}

// Display red flags
function displayRedFlags(contentAnalysis) {
    const redFlagsList = document.getElementById('redFlagsList');

    if (!redFlagsList) return;

    redFlagsList.innerHTML = '';

    // Add keyword flags
    if (contentAnalysis.keyword_analysis && contentAnalysis.keyword_analysis.found_keywords) {
        contentAnalysis.keyword_analysis.found_keywords.forEach(flag => {
            const li = document.createElement('li');
            li.textContent = `${flag.keyword} (weight: ${flag.weight})`;
            li.style.color = flag.severity === 'high' ? '#ef4444' :
                flag.severity === 'medium' ? '#f59e0b' : '#fbbf24';
            redFlagsList.appendChild(li);
        });
    }

    // Add email flags
    if (contentAnalysis.email_analysis && contentAnalysis.email_analysis.reasons) {
        contentAnalysis.email_analysis.reasons.forEach(reason => {
            const li = document.createElement('li');
            li.textContent = reason;
            li.style.color = '#ef4444';
            redFlagsList.appendChild(li);
        });
    }
}

// Display recommendations
function displayRecommendations(recommendations) {
    const recommendationsList = document.getElementById('recommendationsList');

    if (!recommendationsList || !recommendations) return;

    recommendationsList.innerHTML = '';

    recommendations.forEach(rec => {
        const li = document.createElement('li');
        li.textContent = rec;
        recommendationsList.appendChild(li);
    });
}

function toggleUnverifiableState(isUnverifiable) {
    if (riskScoreContainer) {
        riskScoreContainer.style.display = isUnverifiable ? 'block' : 'flex';
    }
    if (riskScoreCircle) {
        riskScoreCircle.style.display = isUnverifiable ? 'none' : 'flex';
    }
    if (analysisConfidence) {
        analysisConfidence.style.display = isUnverifiable ? 'none' : 'block';
    }
    if (analysisDetailsGrid) {
        analysisDetailsGrid.style.display = isUnverifiable ? 'none' : 'grid';
    }
    if (redFlagsCard) {
        redFlagsCard.style.display = isUnverifiable ? 'none' : 'block';
    }
    if (recommendationsCard) {
        recommendationsCard.style.display = isUnverifiable ? 'none' : 'block';
    }
    if (guidanceCard) {
        guidanceCard.style.display = isUnverifiable ? 'block' : 'none';
    }
    if (!isUnverifiable && guidanceReason) {
        guidanceReason.textContent = 'Why: -';
    }
}

function escapeHtml(value) {
    return value.replace(/[&<>"']/g, character => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    }[character]));
}

function escapeRegExp(value) {
    return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function displayHighlightedText(data) {
    if (!highlightedTextCard || !highlightedText) return;

    const isHighlightedTier = data && (data.risk_level === 'HIGH' || data.risk_level === 'MEDIUM');
    const jobDescription = document.getElementById('jobDescription')?.value.trim() || '';
    const flags = data?.content_analysis?.keyword_analysis?.found_keywords || [];
    const usableFlags = flags
        .filter(flag => flag.keyword && Number(flag.weight) > 0)
        .sort((left, right) => right.keyword.length - left.keyword.length);

    if (!isHighlightedTier || !jobDescription || !usableFlags.length) {
        highlightedText.innerHTML = '';
        highlightedTextCard.style.display = 'none';
        return;
    }

    const escapedDescription = escapeHtml(jobDescription);
    const patterns = usableFlags.map(flag => escapeRegExp(escapeHtml(String(flag.keyword))));
    const highlightPattern = new RegExp(`(${patterns.join('|')})`, 'gi');
    highlightedText.innerHTML = escapedDescription.replace(highlightPattern, matchedText => {
        const matchedFlag = usableFlags.find(flag =>
            escapeHtml(String(flag.keyword)).toLowerCase() === matchedText.toLowerCase()
        );
        const className = Number(matchedFlag?.weight) >= 8 ? 'flag-high' : 'flag-med';
        return `<mark class="${className}">${matchedText}</mark>`;
    });
    highlightedTextCard.style.display = 'block';
}

// Display SOS section for high-risk jobs
function displaySOSAlert(sosMessage) {
    if (!sosAlertBox || !sosMessageText) return;

    if (sosMessage) {
        sosMessageText.value = sosMessage;
        sosAlertBox.style.display = 'block';
    } else {
        sosMessageText.value = '';
        sosAlertBox.style.display = 'none';
    }
}

// Copy SOS message text
async function copySOSMessage() {
    if (!sosMessageText || !sosMessageText.value) return;
    try {
        await navigator.clipboard.writeText(sosMessageText.value);
        if (copySosBtn) {
            const originalText = copySosBtn.textContent;
            copySosBtn.textContent = 'Copied!';
            setTimeout(() => {
                copySosBtn.textContent = originalText;
            }, 1200);
        }
    } catch (error) {
        console.error('Failed to copy SOS message:', error);
        alert('Unable to copy message automatically. Please copy it manually.');
    }
}

// Show loading indicator
function showLoading() {
    if (loadingIndicator) {
        loadingIndicator.style.display = 'block';
    }
    if (resultsSection) {
        resultsSection.style.display = 'none';
    }
}

// Hide loading indicator
function hideLoading() {
    if (loadingIndicator) {
        loadingIndicator.style.display = 'none';
    }
}

// Initialize animations on page load
document.addEventListener('DOMContentLoaded', () => {
    const cards = document.querySelectorAll('.stat-card');
    cards.forEach(card => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(20px)';
        card.style.transition = 'all 0.6s ease';
    });

    setTimeout(() => {
        cards.forEach((card, index) => {
            setTimeout(() => {
                card.style.opacity = '1';
                card.style.transform = 'translateY(0)';
            }, index * 100);
        });
    }, 300);
});

// Smooth scroll for navigation
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({ behavior: 'smooth' });
        }
    });
});