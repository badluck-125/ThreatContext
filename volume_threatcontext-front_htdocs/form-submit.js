/* ThreatContext — shared entry-form submit handler.
 *
 * Any page with <form class="contact-form" data-endpoint="...">
 * gets its fields collected into a JSON object and POSTed to
 * the application tier through the front-tier reverse proxy
 * (/api/index.php/<endpoint>). The JSON answer is displayed in
 * the #form-result box.
 *
 * Conventions:
 *  - empty optional fields are omitted from the payload
 *  - exploit_id / ioc_id are sent as integers
 *  - point_of_interest must be typed as JSON text; it is parsed
 *    and sent as a JSON object (stored as JSONB by the API)
 */
document.addEventListener('DOMContentLoaded', function () {
    var form = document.querySelector('form.contact-form[data-endpoint]');
    if (!form) { return; }

    var result = document.getElementById('form-result');
    var button = form.querySelector('button[type="submit"]');

    form.addEventListener('submit', function (e) {
        e.preventDefault();
        result.textContent = 'Sending...';
        result.className = 'content';

        // Collect form fields; skip empty optional ones
        var payload = {};
        new FormData(form).forEach(function (value, key) {
            if (value !== '') { payload[key] = value; }
        });

        // Numeric identifiers -> integers
        ['exploit_id', 'ioc_id'].forEach(function (f) {
            if (payload[f] !== undefined) {
                payload[f] = parseInt(payload[f], 10);
            }
        });

        // point_of_interest: user types JSON text -> send as object
        if (payload.point_of_interest !== undefined) {
            try {
                payload.point_of_interest = JSON.parse(payload.point_of_interest);
            } catch (err) {
                result.textContent = 'point_of_interest is not valid JSON: ' + err.message;
                result.className = 'content form-error';
                return;
            }
        }

        button.disabled = true;

        fetch('/api/index.php/' + form.dataset.endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        })
        .then(function (resp) {
            return resp.json().then(function (data) {
                return { ok: resp.ok, status: resp.status, data: data };
            });
        })
        .then(function (r) {
            result.textContent = 'HTTP ' + r.status + '\n' + JSON.stringify(r.data, null, 2);
            result.className = 'content ' + (r.ok ? 'form-success' : 'form-error');
        })
        .catch(function (err) {
            result.textContent = 'Request failed: ' + err.message;
            result.className = 'content form-error';
        })
        .finally(function () {
            button.disabled = false;
        });
    });
});
