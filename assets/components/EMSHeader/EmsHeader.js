class EMSHeader extends HTMLElement {
    constructor() {
        super();
    }

    connectedCallback() {
        
	this.isAuthenticated = this.getAttribute("isAuthenticated");

        this.innerHTML = `
        <nav class="navbar navbar-expand-lg" style="background-color: midnightblue;">
        <div class="container-fluid">

          <a class="navbar-brand" href="/home">EMS LOGO</a>
          
        </div>
      </nav>
        
        `;
    }

}

window.customElements.define('ems-header', EMSHeader);

/**
 * 
 * 
 * <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav" aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
            <span class="navbar-toggler-icon"></span>
          </button>
          <div class="collapse navbar-collapse" id="navbarNav">
            <ul class="navbar-nav">
              <li class="nav-item">
                <a class="nav-link active" aria-current="page" href="#">Option 1 Testing</a>
              </li>
              <li class="nav-item">
                <a class="nav-link" href="#">Option 2 Testing</a>
              </li>
              <li class="nav-item">
                <a class="nav-link" href="#">Option 3 Testing</a>
              </li>
              <li class="nav-item">
                <a class="nav-link disabled" href="#" tabindex="-1" aria-disabled="true">Disabled Option</a>
              </li>
            </ul>
          </div>
 */