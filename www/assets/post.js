function sendPostRequest(url, data) {
	data.csrf = '%s';
	fetch(url, {
		method: 'POST',
		headers: {
			'Content-Type':'application/json'
		},
		body: JSON.stringify(data)
	});
}
