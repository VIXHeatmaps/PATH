// ===================== BEGIN BLOCK: SUCCESS REDIRECT TO /path/ =====================
// Assumes you've already validated the user + set the session cookie above.
res.writeHead(302, { Location: '/path/' });
res.end();
return;
// ====================== END BLOCK: SUCCESS REDIRECT TO /path/ ======================
