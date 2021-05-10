$(document).ready(function(){
    $('.sidenav').sidenav();
    var payload = {
        method: 'POST', // or 'PUT'
        headers: {
            'Content-Type': 'application/json',
        },
    }
    
    fetch('/if_logged_in', payload)
    .then(res => res.json())
    .then(res => {
        if (res['success']) {
            const li = $("#nav_dropdown");
            li.innerHTML = "";
            const a = document.createElement('a');
            a.href = "#!";
            a.innerText = "Settings";
            a.setAttribute("class","dropdown-trigger");

            a.setAttribute("data-target","dropdown1");

            const icon = document.createElement('i');
            icon.setAttribute("class","material-icons right");
            icon.innerText="arrow_drop_down";
            
            a.appendChild(icon);
            li.append(a);
            $(".dropdown-trigger").dropdown();
        }
        else{
            console.log("Not logged in !");
            const li = $("#nav_dropdown");
            li.innerHTML = "";
            const a = document.createElement('a');
            a.href = "/login";
            a.innerText = "Log in";
            
            li.append(a);
             
        }
       
    })
    .catch(err => {
        console.log("Error came in new user api");

    });
    
    
     
   
});