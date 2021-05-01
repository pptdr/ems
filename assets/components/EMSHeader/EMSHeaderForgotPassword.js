
class SmartSignalHeaderForgotPassword extends HTMLElement {
    constructor() {
        super();
    }

    connectedCallback() {
	this.isAuthenticated = this.getAttribute("isAuthenticated");
        this.innerHTML = `
        <div class="company-name">
             <span>Smart Signal Traffic System</span>
        </div>`;
    }

}

window.customElements.define('smart-signal-header-forgot-password', SmartSignalHeaderForgotPassword);
