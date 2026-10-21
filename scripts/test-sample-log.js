const fs = require('fs');

async function testUploadSampleLog() {
  const content = fs.readFileSync('uploads/analysis_525fa4dc2e8747e5_1791553903237_sample.log', 'utf8');
  
  const formData = new FormData();
  const blob = new Blob([content], { type: 'text/plain' });
  formData.append('file', blob, 'sample.log');

  const res = await fetch('http://localhost:4000/api/v1/analyses/upload', {
    method: 'POST',
    body: formData,
  });

  const status = res.status;
  const data = await res.json();
  console.log('Upload Status:', status);
  console.log('Upload Response:', JSON.stringify(data, null, 2));
}

testUploadSampleLog().catch(console.error);
