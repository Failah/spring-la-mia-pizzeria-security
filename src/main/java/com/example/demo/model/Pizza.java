package com.example.demo.model;

import java.math.BigDecimal;
import java.util.List;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

@Entity
@Table(name = "pizze")
public class Pizza {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Integer id;

	@NotEmpty(message = "Il nome è obbligatorio")
	@Size(min = 1, max = 50, message = "Il nome non deve contenere più di {max} caratteri")
	private String name;

	private String description;

	@Column(name = "image")
	private String imgURL;

	@NotNull(message = "Il prezzo non può essere vuoto")
	@DecimalMin(value = "0.01", message = "Il prezzo deve essere maggiore di zero")
	private BigDecimal price;

	@OneToMany(mappedBy = "pizza", cascade = CascadeType.ALL)
	private List<SpecialOffer> specialOffer;

	@ManyToMany
	private List<Ingredient> ingredients;

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getDescription() {
		return description;
	}

	public void setId(Integer id) {
		this.id = id;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public String getImgURL() {
		return imgURL;
	}

	public void setImgURL(String imgURL) {
		this.imgURL = imgURL;
	}

	public BigDecimal getPrice() {
		return price;
	}

	public void setPrice(BigDecimal price) {
		this.price = price;
	}

	public Integer getId() {
		return id;
	}

	public List<SpecialOffer> getSpecialOffer() {
		return specialOffer;
	}

	public void setSpecialOffer(List<SpecialOffer> specialOffer) {
		this.specialOffer = specialOffer;
	}

	public List<Ingredient> getIngredients() {
		return ingredients;
	}

	public void setIngredients(List<Ingredient> ingredients) {
		this.ingredients = ingredients;
	}

}
