// API Base URL (change if deploying)
const API_BASE_URL = 'http://localhost:8000';

// Smooth scroll to analyze section
function scrollToAnalyze() {
    document.getElementById('analyze').scrollIntoView({ behavior: 'smooth' });
}

// Form submission handler
document.getElementById('scamForm').addEventListener('submit', async function (e) {
    e.preventDefault();

    // Get form data
    const formData = {
        company_name: document.getElementById('companyName').value,
        email: document.getElementById('email').value,
        phone: document.getElementById('phone').value,
        website: document.getElementById('website').value,
        job_description: document.getElementById('jobDescription').value,
        salary: document.getElementById('salary').value
    };

    // Show loading, hide form and results
    document.getElementById('scamForm').style.display = 'none';
    document.getElementById('results').style.display = 'none';
    document.getElementById('loading').style.display = 'block';

    try {
        // Send to backend
        const response = await fetch(`${API_BASE_URL}/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(formData)
        });

        if (!response.ok) {
            throw new Error('Analysis failed');
        }

        const data = await response.json();

        // Hide loading, show results
        document.getElementById('loading').style.display = 'none';
        document.getElementById('results').style.display = 'block';

        // Display results
        displayResults(data);

        // Scroll to results
        document.getElementById('results').scrollIntoView({ behavior: 'smooth' });

    } catch (error) {
        console.error('Error:', error);
        alert('Analysis failed. Please try again.');
        document.getElementById('loading').style.display = 'none';
        document.getElementById('scamForm').style.display = 'block';
    }
});

// Display analysis results
function displayResults(data) {
    // Update risk score circle
    const riskScore = data.overall_risk_score;
    const riskCircle = document.getElementById('riskScoreCircle');
    const riskValue = document.getElementById('riskScoreValue');
    const riskLevel = document.getElementById('riskLevel');
    const verdict = document.getElementById('verdict');

    // Animate score
    animateValue(riskValue, 0, riskScore, 1000);

    // Set color based on risk
    let gradientColor;
    if (riskScore >= 70) {
        gradientColor = '#ef4444'; // Red
        riskLevel.textContent = 'HIGH RISK';
        riskLevel.className = 'text-danger';
    } else if (riskScore >= 40) {
        gradientColor = '#f59e0b'; // Orange
        riskLevel.textContent = 'MEDIUM RISK';
        riskLevel.className = 'text-warning';
    } else {
        gradientColor = '#10b981'; // Green
        riskLevel.textContent = 'LOW RISK';
        riskLevel.className = 'text-success';
    }

    // Update circle gradient
    const degrees = (riskScore / 100) * 360;
    riskCircle.style.background = `conic-gradient(${gradientColor} ${degrees}deg, var(--border-color) ${degrees}deg)`;

    verdict.textContent = data.verdict;

    // Display URL analysis
    displayURLAnalysis(data.url_analysis);

    // Display content analysis
    displayContentAnalysis(data.content_analysis);

    // Display red flags
    displayRedFlags(data.content_analysis);

    // Display recommendations
    displayRecommendations(data.recommendations);
}

// Animate number value
function animateValue(element, start, end, duration) {
    const range = end - start;
    const increment = end > start ? 1 : -1;
    const stepTime = Math.abs(Math.floor(duration / range));
    let current = start;

    const timer = setInterval(() => {
        current += increment;
        element.textContent = Math.round(current);
        if (current === end) {
            clearInterval(timer);
        }
    }, stepTime);
}

// Display URL analysis
function displayURLAnalysis(urlData) {
    const container = document.getElementById('urlAnalysis');

    if (!urlData || Object.keys(urlData).length === 0) {
        container.innerHTML = '<p class="text-secondary">No website provided</p>';
        return;
    }

    let html = '';

    // Domain age
    if (urlData.domain_age && urlData.domain_age.status === 'success') {
        const age = urlData.domain_age.age_days;
        const ageClass = age > 365 ? 'text-success' : age > 180 ? 'text-warning' : 'text-danger';
        html += `
            <div class="analysis-item">
                <strong>Domain Age:</strong> 
                <span class="${ageClass}">${age} days (${urlData.domain_age.creation_date})</span>
            </div>
        `;
    }

    // SSL Certificate
    if (urlData.ssl_certificate) {
        const sslClass = urlData.ssl_certificate.has_ssl ? 'text-success' : 'text-danger';
        const sslIcon = urlData.ssl_certificate.has_ssl ? '✓' : '✗';
        html += `
            <div class="analysis-item">
                <strong>SSL Certificate:</strong> 
                <span class="${sslClass}">${sslIcon} ${urlData.ssl_certificate.has_ssl ? 'Valid HTTPS' : 'No HTTPS'}</span>
            </div>
        `;
    }

    // VirusTotal
    if (urlData.virustotal && urlData.virustotal.status === 'success') {
        const malicious = urlData.virustotal.malicious;
        const vtClass = malicious > 0 ? 'text-danger' : 'text-success';
        html += `
            <div class="analysis-item">
                <strong>Security Scan:</strong> 
                <span class="${vtClass}">${malicious} malicious detections</span>
            </div>
        `;
    }

    // Overall URL risk
    html += `
        <div class="analysis-item" style="margin-top: 15px; padding-top: 15px; border-top: 1px solid var(--border-color)">
            <strong>URL Risk Score:</strong> 
            <span class="badge ${urlData.overall_risk_score >= 50 ? 'badge-high' : urlData.overall_risk_score >= 25 ? 'badge-medium' : 'badge-low'}">
                ${urlData.overall_risk_score}/100
            </span>
        </div>
    `;

    container.innerHTML = html;
}

// Display content analysis
function displayContentAnalysis(contentData) {
    const container = document.getElementById('contentAnalysis');

    let html = `
        <div class="analysis-item">
            <strong>Red Flags Found:</strong> 
            <span class="${contentData.keyword_analysis.flag_count > 3 ? 'text-danger' : 'text-warning'}">
                ${contentData.keyword_analysis.flag_count} suspicious patterns
            </span>
        </div>
    `;

    // Email analysis
    if (contentData.email_analysis.is_suspicious) {
        html += `
            <div class="analysis-item">
                <strong>Email:</strong> 
                <span class="text-danger">⚠️ Suspicious domain</span>
            </div>
        `;
    } else {
        html += `
            <div class="analysis-item">
                <strong>Email:</strong> 
                <span class="text-success">✓ Appears legitimate</span>
            </div>
        `;
    }

    // Salary analysis
    if (contentData.salary_analysis.detected_salary) {
        const salary = contentData.salary_analysis.detected_salary;
        const salaryClass = contentData.salary_analysis.risk_score > 20 ? 'text-warning' : 'text-success';
        html += `
            <div class="analysis-item">
                <strong>Salary:</strong> 
                <span class="${salaryClass}">₹${salary.toLocaleString()}</span>
            </div>
        `;
    }

    // Overall content risk
    html += `
        <div class="analysis-item" style="margin-top: 15px; padding-top: 15px; border-top: 1px solid var(--border-color)">
            <strong>Content Risk Score:</strong> 
            <span class="badge ${contentData.overall_risk_score >= 60 ? 'badge-high' : contentData.overall_risk_score >= 30 ? 'badge-medium' : 'badge-low'}">
                ${contentData.overall_risk_score}/100
            </span>
        </div>
    `;

    container.innerHTML = html;
}

// Display red flags
function displayRedFlags(contentData) {
    const container = document.getElementById('redFlags');
    const flags = contentData.keyword_analysis.detected_flags;

    if (flags.length === 0) {
        container.innerHTML = '<p class="text-success"><i class="fas fa-check-circle"></i> No major red flags detected</p>';
        return;
    }

    let html = '<ul>';
    flags.forEach(flag => {
        const icon = flag.severity === 'high' ? '🚨' : flag.severity === 'medium' ? '⚠️' : 'ℹ️';
        html += `
            <li>
                <span>${icon}</span>
                <div>
                    <strong>${flag.keyword}</strong>
                    <span class="badge ${flag.severity === 'high' ? 'badge-high' : flag.severity === 'medium' ? 'badge-medium' : 'badge-low'}">
                        +${flag.score} risk
                    </span>
                </div>
            </li>
        `;
    });
    html += '</ul>';

    container.innerHTML = html;
}

// Display recommendations
function displayRecommendations(recommendations) {
    const container = document.getElementById('recommendations');

    let html = '<ul>';
    recommendations.forEach(rec => {
        html += `<li><i class="fas fa-lightbulb"></i> ${rec}</li>`;
    });
    html += '</ul>';

    container.innerHTML = html;
}

// Reset form
function resetForm() {
    document.getElementById('scamForm').reset();
    document.getElementById('results').style.display = 'none';
    document.getElementById('scamForm').style.display = 'block';
    document.getElementById('home').scrollIntoView({ behavior: 'smooth' });
}

// Add smooth reveal animation on scroll
window.addEventListener('scroll', () => {
    const elements = document.querySelectorAll('.stat-card, .feature-card, .analysis-card');
    elements.forEach(element => {
        const elementTop = element.getBoundingClientRect().top;
        const windowHeight = window.innerHeight;
        if (elementTop < windowHeight - 100) {
            element.style.opacity = '1';
            element.style.transform = 'translateY(0)';
        }
    });
});

// Initialize animations
document.addEventListener('DOMContentLoaded', () => {
    const cards = document.querySelectorAll('.stat-card, .feature-card');
    cards.forEach(card => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(20px)';
        card.style.transition = 'all 0.6s ease';
    });
});