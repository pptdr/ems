
class SmartSignalHeader extends HTMLElement {
    constructor() {
        super();
    }

    connectedCallback() {
	this.isAuthenticated = this.getAttribute("isAuthenticated");
        this.innerHTML = `
        <div class="company-name">
            <div class="dropdown user-dropdown">
                <button class="btn btn-primary dropdown-toggle" type="button" data-toggle="dropdown">Hello, ${this.getAttribute("name")}
                    <span class="caret"></span>
                </button>
                <ul class="dropdown-menu topnav-right">
                    <li><a href="home">Home</a></li>
                    <li><a href="about">About</a></li>
                </ul>
            </div>

            <span> Smart Signal Traffic System </span>
		    ${this.isAuthenticated ?

                    `<button type="button" class="btn btn-primary logout-button"><a href="/logout">Logout</a></button>`
                                    :``
                    }
        </div>`;
    }

}

window.customElements.define('smart-signal-header', SmartSignalHeader);
