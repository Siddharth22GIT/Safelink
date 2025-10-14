
const navbar = document.querySelector('.navbar');
const menuToggle = document.querySelector('.menu-toggle');
const navLinks = document.querySelector('.nav-links');
const logo = document.querySelector('.logo');
const checkBtn = document.getElementById('check-btn');
const urlInput = document.getElementById('url-input');
const resultCard = document.getElementById('result-card');
const scoreBar = document.getElementById('score-bar');
const scoreValue = document.querySelector('.score-value');
const featureCards = document.querySelectorAll('.feature-card');
const particlesContainer = document.getElementById('particles-container');


menuToggle.addEventListener('click', () => {
    navLinks.classList.toggle('active');
    menuToggle.querySelector('i').classList.toggle('fa-bars');
    menuToggle.querySelector('i').classList.toggle('fa-times');
});


document.addEventListener('click', (e) => {
    if (navLinks.classList.contains('active') && 
        !navLinks.contains(e.target) && 
        !menuToggle.contains(e.target)) {
        navLinks.classList.remove('active');
        menuToggle.querySelector('i').classList.add('fa-bars');
        menuToggle.querySelector('i').classList.remove('fa-times');
    }
});

window.addEventListener('scroll', () => {
    if (window.scrollY > 50) {
        navbar.style.padding = '1rem 2rem';
        navbar.style.boxShadow = '0 4px 20px rgba(0, 0, 0, 0.1)';
    } else {
        navbar.style.padding = '1.5rem 2rem';
        navbar.style.boxShadow = 'none';
    }
});


logo.addEventListener('mouseenter', () => {
    logo.style.transform = 'rotate(5deg) scale(1.05)';
    logo.style.textShadow = '0 0 15px rgba(99, 102, 241, 0.6)';
});

logo.addEventListener('mouseleave', () => {
    logo.style.transform = '';
    logo.style.textShadow = '';
});

function isValidURL(url) {
    try {
        new URL(url);
        return true;
    } catch (e) {
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            try {
                new URL('https://' + url);
                return 'needs-prefix';
            } catch (e) {
                return false;
            }
        }
        return false;
    }
}

function checkURLSafety(url) {
   
    const urlValidation = isValidURL(url);
    
    if (urlValidation === false) {
       
        resultCard.innerHTML = `
            <p class="result-header danger">❌ Invalid URL Format</p>
            <div class="safety-summary">Please enter a valid URL format (e.g., example.com or https://example.com)</div>
            <div class="recommendations">
                <h3>Suggestions</h3>
                <ul>
                    <li>Make sure the URL is correctly formatted (e.g., example.com or https://example.com)</li>
                    <li>Check for typos or extra spaces</li>
                    <li>Include the domain extension (.com, .org, etc.)</li>
                </ul>
            </div>
        `;
        resultCard.style.display = 'block';
        return;
    }
    

    if (urlValidation === 'needs-prefix') {
        url = 'https://' + url;
    }

    resultCard.innerHTML = `
        <div class="loader"></div>
        <p>Analyzing URL safety...</p>
    `;
    resultCard.style.display = 'block';

    setTimeout(() => {
       
        const analysis = analyzeURL(url);
        
        
        updateResultCard(analysis, url);
    }, 1500); 
}

function analyzeURL(url) {
    
    const analysis = {
        isSafe: true,
        score: 0,
        details: [],
        summary: '',
        reasons: []
    };
    

    if (url.includes('phishing') || url.includes('scam')) {
        analysis.isSafe = false;
        analysis.details.push({
            type: 'warning',
            message: 'Potential phishing keywords detected in URL'
        });
        analysis.reasons.push('Contains suspicious keywords that are commonly used in phishing attempts');
    }
    

    const suspiciousTLDs = ['.xyz', '.tk', '.ml', '.ga', '.cf'];
    if (suspiciousTLDs.some(tld => url.endsWith(tld))) {
        analysis.isSafe = false;
        analysis.details.push({
            type: 'warning',
            message: 'Domain uses a potentially suspicious TLD'
        });
        analysis.reasons.push('Uses a top-level domain (.'+url.split('.').pop()+') that is frequently associated with malicious websites');
    }
    

    if (url.startsWith('http:') && !url.startsWith('https:')) {
        analysis.details.push({
            type: 'info',
            message: 'Connection is not secure (HTTP instead of HTTPS)'
        });
        analysis.reasons.push('Uses HTTP instead of HTTPS, which means data is not encrypted during transmission');
    }
    

    const domainParts = url.replace('http://', '').replace('https://', '').split('/')[0].split('.');
    if (domainParts.length > 3) {
        analysis.details.push({
            type: 'info',
            message: 'URL contains multiple subdomains which can be suspicious'
        });
        analysis.reasons.push('Contains multiple subdomains ('+domainParts.length+'), which is a common tactic in phishing URLs');
    }

    const ipPattern = /^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;
    if (ipPattern.test(url)) {
        analysis.isSafe = false;
        analysis.details.push({
            type: 'warning',
            message: 'URL uses an IP address instead of a domain name'
        });
        analysis.reasons.push('Uses an IP address instead of a domain name, which is often a sign of a malicious website');
    }

    const shortenerDomains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'cli.gs', 'ow.ly'];
    const domain = url.replace('http://', '').replace('https://', '').split('/')[0];
    
    if (shortenerDomains.some(shortener => domain.includes(shortener))) {
        analysis.details.push({
            type: 'info',
            message: 'URL uses a shortening service which can hide the actual destination'
        });
        analysis.reasons.push('Uses a URL shortening service, which can hide the actual destination of the link');
    }
    

    const safeDomains = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com', 'github.com'];
    
    if (safeDomains.some(safeDomain => domain.endsWith(safeDomain))) {
        analysis.details.push({
            type: 'success',
            message: 'Domain is a well-known legitimate website'
        });
        analysis.reasons.push('Belongs to a well-known legitimate website with established security practices');
    }

    if (url.startsWith('https:')) {
        analysis.details.push({
            type: 'success',
            message: 'Connection is secure (HTTPS)'
        });
        analysis.reasons.push('Uses HTTPS, which encrypts data during transmission and verifies website identity');
    }

    if (analysis.isSafe) {

        analysis.score = 85;

        if (url.startsWith('https:')) {
            analysis.score += 10;
        }
        

        if (safeDomains.some(safeDomain => domain.endsWith(safeDomain))) {
            analysis.score += 5;
        }
    } else {
      
        analysis.score = 40;
        
      
        const warningCount = analysis.details.filter(detail => detail.type === 'warning').length;
        analysis.score -= warningCount * 15;
        
     
        analysis.score = Math.max(0, analysis.score);
    }
    

    if (analysis.score >= 90) {
        analysis.summary = 'This link appears to be very safe. It uses secure protocols and belongs to a trusted domain.';
    } else if (analysis.score >= 70) {
        analysis.summary = 'This link appears to be safe, but always exercise normal caution when clicking links.';
    } else if (analysis.score >= 40) {
        analysis.summary = 'This link has some concerning elements. Exercise caution before proceeding.';
    } else {
        analysis.summary = 'This link has multiple red flags and may be unsafe. We recommend avoiding this link.';
    }
    
    return analysis;
}

function updateResultCard(analysis, url) {
 
    let resultHTML = '';
    

    if (analysis.score >= 70) {
        resultHTML += `<p class="result-header safe">✅ This link appears to be safe</p>`;
    } else if (analysis.score >= 40) {
        resultHTML += `<p class="result-header caution">⚠️ Exercise caution with this link</p>`;
    } else {
        resultHTML += `<p class="result-header danger">❌ This link may be unsafe</p>`;
    }
    

    resultHTML += `<div class="safety-summary">${analysis.summary}</div>`;
    

    resultHTML += `
        <div class="safety-score">
            <p>Safety Score</p>
            <div class="score-bar-container">
                <div class="score-bar" id="score-bar"></div>
            </div>
            <p class="score-value">${analysis.score}%</p>
        </div>
    `;
    

    resultHTML += `<div class="safety-report">`;
    resultHTML += `<h3>Why is this ${analysis.score >= 70 ? 'safe' : 'potentially unsafe'}?</h3>`;
    resultHTML += `<ul>`;
    
    if (analysis.reasons.length > 0) {
        analysis.reasons.forEach(reason => {
            resultHTML += `<li>${reason}</li>`;
        });
    } else {
        resultHTML += `<li>No specific safety factors were identified.</li>`;
    }
    
    resultHTML += `</ul></div>`;

    if (analysis.details.length > 0) {
        resultHTML += `<div class="analysis-details">`;
        resultHTML += `<h3>Detailed Analysis</h3>`;
        resultHTML += `<ul>`;
        
        analysis.details.forEach(detail => {
            resultHTML += `<li class="${detail.type}"><span class="detail-icon">${
                detail.type === 'warning' ? '⚠️' : 
                detail.type === 'info' ? 'ℹ️' : 
                '✅'
            }</span> ${detail.message}</li>`;
        });
        
        resultHTML += `</ul></div>`;
    }
    
    resultHTML += `
        <div class="recommendations">
            <h3>Recommendations</h3>
            <ul>
    `;
    
    if (analysis.score < 70) {
        resultHTML += `<li>⚠️ Verify the sender's identity before clicking</li>`;
        resultHTML += `<li>⚠️ Check for misspellings in the domain name</li>`;
        resultHTML += `<li>⚠️ Don't enter personal information unless you're certain the site is legitimate</li>`;
    } else {
        resultHTML += `<li>✅ The link appears legitimate, but always stay vigilant</li>`;
    }
    
    resultHTML += `</ul></div>`;
    

    resultHTML += `
        <div class="action-buttons">
            <button id="visit-btn" class="visit-btn ${analysis.score < 40 ? 'dangerous' : ''}">
                ${analysis.score < 40 ? '⚠️ Visit at Your Own Risk' : '🔗 Visit Link'}
            </button>
            <button id="copy-btn" class="copy-btn">📋 Copy Link</button>
        </div>
    `;

    resultCard.innerHTML = resultHTML;
    

    const scoreBar = document.getElementById('score-bar');
    scoreBar.style.width = '0%';
    

    if (analysis.score >= 70) {
        scoreBar.style.backgroundColor = '#10b981';
    } else if (analysis.score >= 40) {
        scoreBar.style.backgroundColor = '#f59e0b'; 
    } else {
        scoreBar.style.backgroundColor = '#ef4444'; 
    }
    

    setTimeout(() => {
        scoreBar.style.width = `${analysis.score}%`;
    }, 100);
    

    document.getElementById('visit-btn').addEventListener('click', () => {
        window.open(url, '_blank');
    });
    
    document.getElementById('copy-btn').addEventListener('click', () => {
        navigator.clipboard.writeText(url).then(() => {
            const copyBtn = document.getElementById('copy-btn');
            copyBtn.textContent = '✅ Copied!';
            setTimeout(() => {
                copyBtn.textContent = '📋 Copy Link';
            }, 2000);
        });
    });
}

checkBtn.addEventListener('click', () => {
    const url = urlInput.value.trim();
    
    if (url === '') {

        checkBtn.classList.add('shake');
        setTimeout(() => {
            checkBtn.classList.remove('shake');
        }, 500);
        return;
    }
    
    checkURLSafety(url);
});

urlInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        e.preventDefault();
        const url = urlInput.value.trim();
        
        if (url !== '') {
            checkURLSafety(url);
        }
    }
});

const observerOptions = {
    threshold: 0.2,
    rootMargin: '0px 0px -50px 0px'
};

const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.classList.add('visible');
            observer.unobserve(entry.target);
        }
    });
}, observerOptions);

featureCards.forEach(card => {
    observer.observe(card);

    const index = Array.from(featureCards).indexOf(card);
    card.style.transitionDelay = `${index * 0.1}s`;
});


function createParticles() {
    const particleCount = 50;
    
    for (let i = 0; i < particleCount; i++) {
        const particle = document.createElement('div');
        particle.classList.add('particle');

        const posX = Math.random() * 100;
        const posY = Math.random() * 100;

        const size = Math.random() * 5 + 2;

        const opacity = Math.random() * 0.5 + 0.3;

        const duration = Math.random() * 20 + 10;

        particle.style.cssText = `
            position: absolute;
            top: ${posY}%;
            left: ${posX}%;
            width: ${size}px;
            height: ${size}px;
            background: white;
            border-radius: 50%;
            opacity: ${opacity};
            pointer-events: none;
            animation: float ${duration}s infinite ease-in-out;
        `;
        
        particlesContainer.appendChild(particle);
    }
}


const style = document.createElement('style');
style.textContent = `
    @keyframes float {
        0%, 100% {
            transform: translateY(0) translateX(0);
        }
        25% {
            transform: translateY(-20px) translateX(10px);
        }
        50% {
            transform: translateY(-10px) translateX(-15px);
        }
        75% {
            transform: translateY(-25px) translateX(5px);
        }
    }
    
    @keyframes shake {
        0%, 100% { transform: translateX(0); }
        25% { transform: translateX(-5px); }
        50% { transform: translateX(5px); }
        75% { transform: translateX(-5px); }
    }
    
    .shake {
        animation: shake 0.5s ease-in-out;
    }
`;

document.head.appendChild(style);

window.addEventListener('load', () => {
    createParticles();
    

    document.body.style.opacity = 0;
    setTimeout(() => {
        document.body.style.transition = 'opacity 1s ease';
        document.body.style.opacity = 1;
    }, 100);
});


document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
        e.preventDefault();
        
        const targetId = this.getAttribute('href');
        if (targetId === '#') return;
        
        const targetElement = document.querySelector(targetId);
        if (targetElement) {
            window.scrollTo({
                top: targetElement.offsetTop - 100,
                behavior: 'smooth'
            });
            

            if (navLinks.classList.contains('active')) {
                navLinks.classList.remove('active');
                menuToggle.querySelector('i').classList.add('fa-bars');
                menuToggle.querySelector('i').classList.remove('fa-times');
            }
        }
    });
});