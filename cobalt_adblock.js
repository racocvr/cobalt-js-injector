setInterval(() => {        
    if (document.getElementsByClassName("ad-showing").length > 0) {
		document.getElementsByClassName('html5-main-video')[0].currentTime = document.getElementsByClassName('html5-main-video')[0].duration;
    }
}, 50)