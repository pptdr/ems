{% load static %}
class SmartSignalSidebar extends HTMLElement {
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
                            <h4 class="panel-title"  data-target="#uploadDownloadVideos">
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
                                <i class="fa fa-upload" aria-hidden="true"></i>
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
                        </div>
                    </div>
                </div>
            </div>
     /*   <div>
            <img src = "/static/images/dpifs.jpeg" width="80" height="80">
	  </div>  */
        </div>`;
    }

}

window.customElements.define('smart-signal-sidebar', SmartSignalSidebar);
