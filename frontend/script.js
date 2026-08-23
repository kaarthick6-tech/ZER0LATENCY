// API Base URL
const API_BASE_URL = 'http://127.0.0.1:8001';

// DOM Elements
const analyzeBtn = document.getElementById('analyzeBtn');
const loadingIndicator = document.getElementById('loadingIndicator');
const resultsSection = document.getElementById('resultsSection');
const riskScoreValue = document.getElementById('riskScoreValue');
const riskScoreCircle = document.getElementById('riskScoreCircle');
const riskLevel = document.getElementById('riskLevel');
const verdict = document.getElementById('verdict');

// Analyze button click handler
if (analyzeBtn) {
    analyzeBtn.addEventListener('click', analyzeOpportunity);
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
        const response = await fetch(`${API_BASE_URL}/analyze`, {
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
    // Update risk score circle
    const riskScore = Math.min(100, Math.max(0, Number(data.overall_risk_score) || 0));

    console.log('Risk Score:', riskScore); // Debug log

    // Animate score
    animateValue(riskScoreValue, 0, Math.round(riskScore), 1000);

    // Set color based on risk (FIXED)
    let gradientColor;
    let riskText;

    if (riskScore >= 70) {
        gradientColor = '#ef4444'; // Red - HIGH RISK
        riskText = 'HIGH RISK';
        riskLevel.className = 'risk-level text-danger';
    } else if (riskScore >= 40) {
        gradientColor = '#f59e0b'; // Orange - MEDIUM RISK
        riskText = 'MEDIUM RISK';
        riskLevel.className = 'risk-level text-warning';
    } else {
        gradientColor = '#10b981'; // Green - LOW RISK
        riskText = 'LOW RISK';
        riskLevel.className = 'risk-level text-success';
    }

    // Update circle gradient (FIXED - use proper percentage)
    const degrees = (riskScore / 100) * 360;
    riskCircle.style.background = `conic-gradient(${gradientColor} ${degrees}deg, var(--border-color) ${degrees}deg)`;

    riskLevel.textContent = riskText;
    verdict.textContent = data.verdict;

    // Display URL analysis
    displayURLAnalysis(data.url_analysis);

    // Display content analysis
    displayContentAnalysis(data.content_analysis);

    // Display red flags
    displayRedFlags(data.content_analysis);

    // Display recommendations
    displayRecommendations(data.recommendations);

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