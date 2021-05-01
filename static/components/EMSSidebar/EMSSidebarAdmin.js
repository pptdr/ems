class SmartSignalSidebarAdmin extends HTMLElement {
    constructor() {
        super();
    }

    connectedCallback() {
        this.innerHTML = `
         <div class="sidenav-left">
	    <div class="panel-dropdown">
                <div class="panel-group" id="accordion">
                    <div class="panel panel-default">
                        <div class="panel-heading">
                            <h4 class="panel-title" data-toggle="collapse" data-target="#clients">
                                <i class="fa fa-user-circle" aria-hidden="true"></i>
                                <span class="panel-dropdown-text">Clients</span>
                            </h4>
                        </div>
                        <div id="clients" class="panel-collapse collapse in">
                            <div class="panel-body">
                                <i class="fa fa-user-plus" aria-hidden="true"></i>
                                <a href="addclient">
                                    <span class="panel-dropdown-text">
                                        Add Client
                                    </span>
                                </a>
                            </div>
                            <div class="panel-body">
                                <i class="fa fa-users" aria-hidden="true"></i>
                                <a href="show_clients">
                                    <span class="panel-dropdown-text">
                                        Show All Clients
                                    </span>
                                </a>
                            </div>
                            <div class="panel-body">
                                <i class="fa fa-television" aria-hidden="true"></i>
                                <a href="show_signals">
                                    <span class="panel-dropdown-text">
                                        Show All Signals
                                    </span>
                                </a>
                            </div>
                            <div class="panel-body">
                                <i class="fa fa-user-times" aria-hidden="true"></i>
                                <a href="show_clients">
                                    <span class="panel-dropdown-text">
                                        Delete Client
                                    </span>
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <div class="panel-dropdown">
                <div class="panel-group" id="accordion">
                    <div class="panel panel-default">
                        <div class="panel-heading">
                            <h4 class="panel-title" data-toggle="collapse" data-target="#uploadDownloadVideos">
                                <i class="fa fa-video-camera" aria-hidden="true"></i>
                                <span class="panel-dropdown-text">Upload/List Videos</span>
                            </h4>
                        </div>
                        <div id="uploadDownloadVideos" class="panel-collapse collapse in">
                            <div class="panel-body">
                                <i class="fa fa-upload" aria-hidden="true"></i>
                                <a href="uploadvideo1">
                                    <span class="panel-dropdown-text">
                                        Upload a video
                                    </span>
                                </a>
                            </div>
                            <div class="panel-body">
                                <i class="fa fa-list" aria-hidden="true"></i>
                                <a href="displaylist_admin">
                                    <span class="panel-dropdown-text">
                                        List out videos
                                    </span>
                                </a>
                            </div>
			    <div class="panel-body">
                                <i class="fas fa-map-marker" aria-hidden="true"></i>
                                <a href="admin_map">
                                    <span class="panel-dropdown-text">
                                        Show map
                                    </span>
                                </a>
                            </div>

			 </div>
                    </div>
                </div>
            </div>  
	 </div>`;
	}


}

window.customElements.define('smart-signal-sidebar-admin', SmartSignalSidebarAdmin);

