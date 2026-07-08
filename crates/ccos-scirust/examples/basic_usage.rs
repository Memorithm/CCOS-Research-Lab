//! SLHA v2 Examples
//!
//! Demonstrates basic usage of the SLHA v2 attention scorer.

use scirust::attention::slha_v2::SciRustSlhaTile;

fn main() {
    // Build a tile from quantized latent
    let v: Vec<f32> = (0..128).map(|i| ((i as f32) - 64.0) / 16.0).collect();
    let mut varr = [0.0f32; 128];
    varr.copy_from_slice(&v);
    let (packed, scale) = scirust::attention::slha_v2::quantize_latent(&varr);

    let tile = SciRustSlhaTile {
        latent_kv: packed,
        residual_bitmap: [0u64; 4],
        scale,
        dynamic_lambda: 0.5,
        residual_sigma: 0.0,
        token_id: 0,
        position: 0,
        head_id: 0,
        flags: scirust::attention::slha_v2::FLAG_HOT,
        group_scales: [255u8; 8],
    };

    let mut q_coarse = [0.0f32; 128];
    q_coarse[0] = 1.0;
    q_coarse[1] = 1.0;
    let q_sign = [0x1234_5678_9ABC_DEF0u64; 4];

    // Compute score (auto-dispatch: AVX2/AVX512/NEON/scalar)
    let score = tile.compute_score(&q_coarse, &q_sign);
    println!("Score: {:.6}", score);

    // Check tile state
    if tile.is_warm() {
        println!("Tile is in WARM mode (latent only)");
    } else {
        println!("Tile is in HOT mode (full fidelity)");
    }

    // Materialize the dequantized latent vector
    let latent = tile.dequant_latent();
    println!("Dequantized latent[0..4]: {:?}", &latent[..4]);
}
