(function() {
	// Realtime clock, inserted every second
	var live_clock = document.querySelector('digiclock');
	var refresh_clock = document.getElementById('refreshclock');
	
	var pad = function(x) {
		return x < 10 ? '0'+x : x;
	};
	
	var ticktock = function(clock_name) {
		var d = new Date();
		
		var h = pad( d.getHours() );
		var m = pad( d.getMinutes() );
		var s = pad( d.getSeconds() );
		
		var current_time = [h,m,s].join(':');
		
		clock_name.innerHTML = current_time;
		
	};
	
	ticktock(refresh_clock);
	ticktock(live_clock);
	
	// Calling ticktock() every 1 second
	setInterval(function() { ticktock(live_clock); }, 1000);
	
}());
