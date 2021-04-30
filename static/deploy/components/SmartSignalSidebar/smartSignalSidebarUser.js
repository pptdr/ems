const CLIENT_LOGO_MAP = {
        /* Make sure user name matches with user ID login*/
        'sdpm' : '/static/images/Ecube_logo.png',
        'dpifs' : '/static/images/dpifs.jpeg',
        'client3' : '/static/images/dpifs.jpeg'
}

class SmartSignalSidebarUser extends HTMLElement {
    constructor() {
        super();
    }

    connectedCallback() {

	this.logoUrl = CLIENT_LOGO_MAP[this.getAttribute("name")];

        this.innerHTML = `
        <div class="sidenav-left">
            <div class="panel-dropdown">
                <div class="panel-group" id="accordion">
                    <div class="panel panel-default">
                        <div class="panel-heading">
                            <h4 class="panel-title"  data-target="#uploadDownloadVideos">
                                <i class="fa fa-video-camera" aria-hidden="true"></i>
                                <span class="panel-dropdown-text">Navigation panel</span>
                            </h4>
                        </div>
                        <div id="uploadDownloadVideos" class="panel-collapse collapse in">
                            <div class="panel-body">
                                <i class="fa fa-upload" aria-hidden="true"></i>
                                <a href="new_uploadvideo">
                                    <span class="panel-dropdown-text">
                                        Upload a video
                                    </span>
                                </a>
                            </div>
                     	    <div class="panel-body">
                                <i class="fa fa-cloud-upload" aria-hidden="true"></i>
                                <a href="uploadvideo_at_all_sites">
                                    <span class="panel-dropdown-text">
                                        Upload video at all sites
                                    </span>
                                </a>
                            </div>

                            <div class="panel-body">
                                <i class="fa fa-list" aria-hidden="true"></i>
                                <a href="displaylist_user">
                                    <span class="panel-dropdown-text">
                                        List out videos
                                    </span>
                                </a>
                            </div>
			    <div class="panel-body">
                                <i class="fas fa-map-marker" aria-hidden="true"></i>
                                <a href="get_map">
                                    <span class="panel-dropdown-text">
                                        Show signals on map
                                    </span>
                                </a>
                            </div>
			    <div class="panel-body">
                                <i class="fa fa-camera" aria-hidden="true"></i>
                                <a href="get_cctv_feeds">
                                    <span class="panel-dropdown-text">
                                       CCTV Feeds
                                    </span>
                                </a>
                            </div>
	               </div>
                    </div>
                </div>
            </div>
	   <div>
	        <img src = ${this.logoUrl}  width="180" height="180" style="margin-left: calc(100% - 275px);">
	   </div>
        </div>`;
    }

}

window.customElements.define('smart-signal-sidebar-user', SmartSignalSidebarUser);
