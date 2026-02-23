window.ClientTour = (function () {
    const steps = [
        {
            title: "1. The Access Request",
            desc: "A lawyer clicks on a link to a sensitive case file or tries to log into the firm's central dashboard. Before any data is shown, our system immediately intercepts the request.",
            value: "Ensures that absolutely no one bypasses the front door. The system assumes everyone is a threat until proven otherwise."
        },
        {
            title: "2. Secure Device Handshake",
            desc: "In a fraction of a second, the lawyer's device generates a unique, single-use cryptographical lock and sends it to our system. Our system holds onto it, waiting for the matching key.",
            value: "Guarantees the person who started the login is the exact same person finishing it. It prevents 'man-in-the-middle' attacks where hackers try to intercept the connection from a coffee shop."
        },
        {
            title: "3. Identity Verification (Okta / Microsoft Azure)",
            desc: "The lawyer is securely redirected to the firm's existing trusted Identity Provider. They enter their credentials and perform a biometric scan (FaceID) or tap a security key.",
            value: "Centralizes all security policy. We don't invent new passwords for people to lose; we rely on the firm's existing, hardened corporate identity infrastructure."
        },
        {
            title: "4. The 'Claim Ticket' Issuance",
            desc: "Once Microsoft or Okta verifies the lawyer, they aren't given access to the files yet. They are only given a temporary 'claim ticket' (Authorization Code) and sent back to our system.",
            value: "Stops hackers from stealing a 'skeleton key' during the handover. If the ticket is stolen in transit, it's useless without the secret lock created in Step 2."
        },
        {
            title: "5. The Final Security Swap",
            desc: "Behind closed doors, completely invisible to the internet, our system trades the 'claim ticket' and the 'secret lock' directly with Microsoft/Okta to prove authenticity. Only then is the final Access Pass issued.",
            value: "The most sensitive security materials are never exposed to the lawyer's browser or the public internet, completely neutralizing phishing and interception risks."
        },
        {
            title: "6. Tamper-Proof Digital Badge",
            desc: "Our system creates a secure, encrypted 'badge' (Session Cookie) and pins it to the lawyer's specific browser. As they navigate between case files, they show this badge instead of constantly re-logging in.",
            value: "Creates a frictionless experience for the lawyers while maintaining military-grade security. If a device is lost, the IT team can instantly revoke the badge, locking the device out permanently."
        }
    ];

    let currentStep = 0;
    let tourInterval = null;

    function init() {
        renderTour();

        const tourBtn = document.getElementById('btn-client-tour');
        if (tourBtn) {
            tourBtn.addEventListener('click', () => {
                // Switch to the workflow tab automatically
                document.querySelector('.nav-tab[data-panel="workflow"]').click();
                startTour();
            });
        }
    }

    function renderTour() {
        const step = steps[currentStep];

        // Render left-hand diagram of numbered steps
        const diagram = document.getElementById('client-tour-diagram');
        if (!diagram) return;

        let html = '<div class="sim-flow">';
        steps.forEach((s, i) => {
            let state = i < currentStep ? 'past' : i === currentStep ? 'current' : 'future';
            html += `<div class="sim-flow-step ${state}" style="padding: 20px;">
        <div class="sim-flow-name-wrapper" style="flex-direction: row; align-items: center; gap: 16px;">
          <div class="sim-flow-num" style="width: 32px; height: 32px; font-size: 1rem;">${i < currentStep ? '&#10003;' : i + 1}</div>
          <div class="sim-flow-name" style="font-size: 1.1rem;">${s.title}</div>
        </div>
      </div>`;
            if (i < steps.length - 1) {
                html += `<div class="sim-flow-arrow ${i < currentStep ? 'past' : ''}">&darr;</div>`;
            }
        });
        html += '</div>';
        diagram.innerHTML = html;

        // Render right-hand details
        document.getElementById('client-tour-title').textContent = step.title;
        document.getElementById('client-tour-desc').textContent = step.desc;
        document.getElementById('client-tour-value').textContent = step.value;
    }

    function startTour() {
        const btn = document.getElementById('btn-client-tour');
        const workflowTab = document.querySelector('.nav-tab[data-panel="workflow"]');

        // Switch to workflow panel immediately
        if (workflowTab && !workflowTab.classList.contains('active')) {
            workflowTab.click();
        }

        if (tourInterval) {
            clearInterval(tourInterval);
            tourInterval = null;
            btn.textContent = '▶ Start Tour';
            return;
        }

        currentStep = 0;
        renderTour();
        btn.textContent = '⏹ Stop Tour';

        tourInterval = setInterval(() => {
            if (currentStep < steps.length - 1) {
                currentStep++;
                renderTour();
            } else {
                clearInterval(tourInterval);
                tourInterval = null;
                btn.textContent = '▶ Start Tour';
                currentStep = 0; // Reset for next time
            }
        }, 4000); // 4 seconds per step, enough time to read the plain English text
    }

    return { init, startTour };
})();

// Initialize on DOM Load
document.addEventListener('DOMContentLoaded', () => {
    ClientTour.init();
});
