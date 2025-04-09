// function checkMessage() {
//     let message = document.getElementById("message").value;
    
//     fetch("http://127.0.0.1:8000/", {
//         method: "POST",
//         headers: { "Content-Type": "application/json" },
//         body: JSON.stringify({ message: message })
//     })
//     .then(response => response.json())
//     .then(data => {
//         document.getElementById("result").innerText = "Prediction: " + data.prediction;
//     })
//     .catch(error => {
//         console.error("Error:", error);
//         document.getElementById("result").innerText = "Error making prediction.";
//     });
// }

// Add event listener when the DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('analyzeButton').addEventListener('click', checkMessage);
});

function checkMessage() {
    const message = document.getElementById("message").value;
    const result = document.getElementById("result");
    result.innerHTML = '';

    fetch("http://127.0.0.1:8000/", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message })
    })
    .then(response => response.json())
    .then(data => {
        const messageAnalysis = data.message_analysis;
        const urlAnalysis = data.url_analysis;
        const urlProbability = (data.url_probability * 100).toFixed(2);
        const textProbability = (data.message_probability * 100).toFixed(2);
        const finalResult = data.final_result;
        const finalProbability = (data.final_probability * 100).toFixed(2);
        const summary = data.summary;
        const explanation = data.explanation.trim();
        const metrics = data.performance_metrics;

        let resultText = '';
        if(messageAnalysis) {
            resultText += `<span style="font-weight: 600">Message Analysis:</span> ${messageAnalysis}<br>`;
            resultText += `<span style="font-weight: 600">Message Risk:</span> ${textProbability}%<br>`;
        }

        if (urlAnalysis.length > 0) {
            resultText += `<span style="font-weight: 600">URL Analysis:</span> ${urlAnalysis}<br>`;
            resultText += `<span style="font-weight: 600">URL Risk:</span> ${urlProbability}%<br>`;
        }

        if (explanation) {
            resultText += `<span style="font-weight: 600">Word Analysis:</span> ${explanation}<br>`;
            if (summary) {
                resultText += `<span style="font-weight: 600">Risk summary:</span> ${summary}<br>`;
            }
        }

        resultText += `<br><span style="font-weight: 600">Final Result:</span> ${finalResult}<br>`;
        resultText += `<span style="font-weight: 600">Final Risk:</span> ${finalProbability}%<br>`;

        // Add performance metrics
        // resultText += '<br><div style="font-size: 0.9em; color: #666; margin-top: 10px; border-top: 1px solid #eee; padding-top: 10px;">';
        // resultText += '<span style="font-weight: 600">Performance Metrics:</span><br>';
        // resultText += `Average URL Analysis Time: ${metrics.avg_url_analysis_time_ms}ms<br>`;
        // resultText += `Average Text Analysis Time: ${metrics.avg_text_analysis_time_ms}ms<br>`;
        // resultText += `Average Total Processing Time: ${metrics.avg_total_time_ms}ms<br>`;
        // resultText += `Current Processing Time: ${metrics.current_total_time_ms}ms`;
        // resultText += '</div>';

        result.innerHTML = resultText;
    })
    .catch(error => {
        console.error("Error:", error);
        result.innerHTML = "Error making prediction.";
    });
}


