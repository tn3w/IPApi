use actix_web::{App, HttpResponse, HttpServer, Responder, web};

mod dnsdata;
mod geodata;
mod ipdata;
mod response;

async fn index() -> impl Responder {
    HttpResponse::Ok().body("Hello, World!")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    if let Err(e) = geodata::initialize_geo_databases().await {
        eprintln!("Failed to initialize geo databases: {}", e);
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Database initialization failed",
        ));
    }

    if let Err(e) = ipdata::initialize_tor_database().await {
        eprintln!("Failed to initialize Tor database: {}", e);
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Tor database initialization failed",
        ));
    }

    println!("Server listening on http://127.0.0.1:5000");

    HttpServer::new(|| {
        App::new()
            .route("/", web::get().to(index))
            .route("/self", web::get().to(response::get_self_ip_info))
            .route("/{ip_address}", web::get().to(response::get_ip_info))
    })
    .workers(16)
    .bind("127.0.0.1:5000")?
    .run()
    .await
}
