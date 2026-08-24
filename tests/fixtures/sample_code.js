// SentinelClip Test Fixture — Sample JavaScript Code
// ALL VALUES ARE FAKE — for testing detection rules only.

const config = {
    // Fake API key
    api_key: "sk_test_FAKE_1234567890abcdefghijklm",
    
    // Fake AWS access key
    awsAccessKey: "AKIAIOSFODNN7JSEXAMP",
    
    // Internal server IPs (fake)
    servers: {
        primary: "10.0.1.10",
        replica: "172.16.0.100",
        cache: "192.168.1.50",
    },
    
    // Fake database password
    password: "super_secret_js_password_123",
    
    // Fake JWT
    authToken: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZXN0LXNlcnZpY2UifQ.fake_rsa_sig",
};

// Fake admin email
const adminEmail = "admin@internal-system.example.com";

async function fetchData() {
    const response = await fetch(`https://api.example.com/data`, {
        headers: {
            "Authorization": `Bearer ${config.authToken}`,
            "X-API-Key": config.api_key,
        }
    });
    return response.json();
}

module.exports = { config, fetchData };
