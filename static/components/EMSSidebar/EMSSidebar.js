class EMSSidebar extends HTMLElement {
    constructor() {
        super();
    }

    connectedCallback() {
        this.innerHTML = `
        <div class="sidebar">

          <div class="accordion" id="accordionExample">

            <div class="accordion-item">
                <h2 class="accordion-header" id="headingOne">
                <button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapseOne" aria-expanded="true" aria-controls="collapseOne">
                    PowerMan
                </button>
                </h2>
                <div id="collapseOne" class="accordion-collapse collapse show" aria-labelledby="headingOne" data-bs-parent="#accordionExample">
                    <div class="accordion-body"><div><a href="/cmp" class="opt-a"><span class="panel-dropdown-text">Company</span></a></div></div>
                    <div class="accordion-body"><div><a href="/location" class="opt-a"><span class="panel-dropdown-text">Location</span></a></div></div>
                    <div class="accordion-body"><div><a href="/area" class="opt-a"><span class="panel-dropdown-text">Area</span></a></div></div>
                    <div class="accordion-body"><div><a href="/virtualchannel" class="opt-a"><span class="panel-dropdown-text">Virtual Channel</span></a></div></div>
                    <div class="accordion-body"><div><a href="/emanage" class="opt-a"><span class="panel-dropdown-text">Eamange</span></a></div></div>
                    <div class="accordion-body"><div><a href="/roicalc" class="opt-a"><span class="panel-dropdown-text">ROI Calculator</span></a></div></div>
                </div>
            </div>

            <div class="accordion-item">
              <h2 class="accordion-header" id="headingTwo">
                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseTwo" aria-expanded="false" aria-controls="collapseTwo">
                  Views
                </button>
              </h2>
              <div id="collapseTwo" class="accordion-collapse collapse" aria-labelledby="headingTwo" data-bs-parent="#accordionExample">
                  <div class="accordion-body"><div><a href="/cmp" class="opt-a"><span class="panel-dropdown-text">Company</span></a></div></div>
                  <div class="accordion-body"><div><a href="/cmp" class="opt-a"><span class="panel-dropdown-text">Location</span></a></div></div>
                  <div class="accordion-body"><div><a href="/cmp" class="opt-a"><span class="panel-dropdown-text">Area</span></a></div></div>
                  <div class="accordion-body"><div><a href="/cmp" class="opt-a"><span class="panel-dropdown-text">Virtual Channel</span></a></div></div>
      
              </div>
            </div>

            <div class="accordion-item">
              <h2 class="accordion-header" id="headingThree">
                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseThree" aria-expanded="false" aria-controls="collapseThree">
                  Graphics
                </button>
              </h2>
              <div id="collapseThree" class="accordion-collapse collapse" aria-labelledby="headingThree" data-bs-parent="#accordionExample">
                    <div class="accordion-body"><div><a href="/cmp" class="opt-a"><span class="panel-dropdown-text">Virtual Channel</span></a></div></div>
              </div>
            </div>

            <div class="accordion-item">
              <h2 class="accordion-header" id="headingFour">
                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseFour" aria-expanded="false" aria-controls="collapseFour">
                  Reports
                </button>
              </h2>
              <div id="collapseFour" class="accordion-collapse collapse" aria-labelledby="headingFour" data-bs-parent="#accordionExample">
                    <div class="accordion-body"><div><a href="/cmp" class="opt-a"><span class="panel-dropdown-text">Virtual Channel</span></a></div></div>
              </div>
            </div>


            <div class="accordion-item">
              <h2 class="accordion-header" id="headingFive">
                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseFive" aria-expanded="false" aria-controls="collapseFive">
                  Device Configuration
                </button>
              </h2>
              <div id="collapseFive" class="accordion-collapse collapse" aria-labelledby="headingFive" data-bs-parent="#accordionExample">
                    <div class="accordion-body"><div><a href="/cmp" class="opt-a"><span class="panel-dropdown-text">In Progress</span></a></div></div>
              </div>
            </div>


            <div class="accordion-item">
              <h2 class="accordion-header" id="headingThree">
                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseSix" aria-expanded="false" aria-controls="collapseSix">
                  Controller Configuration
                </button>
              </h2>
              <div id="collapseSix" class="accordion-collapse collapse" aria-labelledby="headingSix" data-bs-parent="#accordionExample">
                    <div class="accordion-body"><div><a href="/cmp" class="opt-a"><span class="panel-dropdown-text">Under Construction</span></a></div></div>
              </div>
            </div>


            <div class="accordion-item">
              <h2 class="accordion-header" id="headingSeven">
                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseSeven" aria-expanded="false" aria-controls="collapseSeven">
                  ACB Reports
                </button>
              </h2>
              <div id="collapseSeven" class="accordion-collapse collapse" aria-labelledby="headingSeven" data-bs-parent="#accordionExample">
                    <div class="accordion-body"><div><a href="/cmp" class="opt-a"><span class="panel-dropdown-text">Under Construction</span></a></div></div>
              </div>
            </div>


            <div class="accordion-item">
              <h2 class="accordion-header" id="headingEight">
                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseEight" aria-expanded="false" aria-controls="collapseEight">
                  Cost Centre
                </button>
              </h2>
              <div id="collapseEight" class="accordion-collapse collapse" aria-labelledby="headingEight" data-bs-parent="#accordionExample">
                    <div class="accordion-body"><div><a href="/cmp" class="opt-a"><span class="panel-dropdown-text">Under Construction</span></a></div></div>
              </div>
            </div>


            <div class="accordion-item">
              <h2 class="accordion-header" id="headingNine">
                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseNine" aria-expanded="false" aria-controls="collapseNine">
                  Advanced
                </button>
              </h2>
              <div id="collapseNine" class="accordion-collapse collapse" aria-labelledby="headingNine" data-bs-parent="#accordionExample">
                    <div class="accordion-body"><div><a href="/cmp" class="opt-a"><span class="panel-dropdown-text">Under Construction</span></a></div></div>
              </div>
            </div>

            <div class="accordion-item">
              <h2 class="accordion-header" id="headingTen">
                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseTen" aria-expanded="false" aria-controls="collapseTen">
                  Action/Event
                </button>
              </h2>
              <div id="collapseTen" class="accordion-collapse collapse" aria-labelledby="headingTen" data-bs-parent="#accordionExample">
                    <div class="accordion-body"><div><a href="/cmp" class="opt-a"><span class="panel-dropdown-text">Under Construction</span></a></div></div>
              </div>
            </div>

            <div class="accordion-item">
              <h2 class="accordion-header" id="headingEleven">
                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseEleven" aria-expanded="false" aria-controls="collapseEleven">
                  Admin Tools
                </button>
              </h2>
              <div id="collapseEleven" class="accordion-collapse collapse" aria-labelledby="headingEleven" data-bs-parent="#accordionExample">
                    <div class="accordion-body"><div><a href="/cmp" class="opt-a"><span class="panel-dropdown-text">Under Construction</span></a></div></div>
              </div>
            </div>


            <div class="accordion-item">
              <h2 class="accordion-header" id="headingTwelve">
                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapseTwelve" aria-expanded="false" aria-controls="collapseTwelve">
                  Administration
                </button>
              </h2>
              <div id="collapseTwelve" class="accordion-collapse collapse" aria-labelledby="headingTwelve" data-bs-parent="#accordionExample">
                    <div class="accordion-body"><div><a href="/cmp" class="opt-a"><span class="panel-dropdown-text">Under Construction</span></a></div></div>
              </div>
            </div>

          </div>
        </div>`;
    }

}

window.customElements.define('ems-sidebar', EMSSidebar);
