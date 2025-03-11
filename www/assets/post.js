async function sendPostRequest(url, data) {
	data.csrf = '%s';
	var r = await fetch(url, {
		method: 'POST',
		headers: {
			'Content-Type':'application/json'
		},
		body: JSON.stringify(data)
	});
	if (r.ok) return;
	if (r.status == 401) {
		alert('This action requires admin access.');
	} else {
		alert('Error ' + r.status);
	}
}
