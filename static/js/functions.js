$( document ).ready(function() {
    console.log( "document loaded" );

    $('.modal').modal();
    $('select').material_select();
    $("select[required]").css({display: "block", height: 0, padding: 0, width: 0, position: 'absolute'}); // https://stackoverflow.com/questions/34248898/how-to-validate-select-option-for-a-materialize-dropdown
    $(".button-collapse").sideNav();
});