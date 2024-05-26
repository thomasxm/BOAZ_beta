import math
import random
import sys

# Assuming PokemonList is already defined as provided in your question

PokemonList = ["Missingno","Bulbasaur","Ivysaur","Venusaur","Charmander","Charmeleon","Charizard","Squirtle","Wartortle","Blastoise","Caterpie","Metapod","Butterfree","Weedle","Kakuna","Beedrill","Pidgey","Pidgeotto","Pidgeot","Rattata","Raticate","Spearow","Fearow","Ekans","Arbok","Pikachu","Raichu","Sandshrew","Sandslash","NidoranF","Nidorina","Nidoqueen","NidoranM","Nidorino","Nidoking","Clefairy","Clefable","Vulpix","Ninetales","Jigglypuff","Wigglytuff","Zubat","Golbat","Oddish","Gloom","Vileplume","Paras","Parasect","Venonat","Venomoth","Diglett","Dugtrio","Meowth","Persian","Psyduck","Golduck","Mankey","Primeape","Growlithe","Arcanine","Poliwag","Poliwhirl","Poliwrath","Abra","Kadabra","Alakazam","Machop","Machoke","Machamp","Bellsprout","Weepinbell","Victreebel","Tentacool","Tentacruel","Geodude","Graveler","Golem","Ponyta","Rapidash","Slowpoke","Slowbro","Magnemite","Magneton","Farfetchd","Doduo","Dodrio","Seel","Dewgong","Grimer","Muk","Shellder","Cloyster","Gastly","Haunter","Gengar","Onix","Drowzee","Hypno","Krabby","Kingler","Voltorb","Electrode","Exeggcute","Exeggutor","Cubone","Marowak","Hitmonlee","Hitmonchan","Lickitung","Koffing","Weezing","Rhyhorn","Rhydon","Chansey","Tangela","Kangaskhan","Horsea","Seadra","Goldeen","Seaking","Staryu","Starmie","Mr. Mime","Scyther","Jynx","Electabuzz","Magmar","Pinsir","Tauros","Magikarp","Gyarados","Lapras","Ditto","Eevee","Vaporeon","Jolteon","Flareon","Porygon","Omanyte","Omastar","Kabuto","Kabutops","Aerodactyl","Snorlax","Articuno","Zapdos","Moltres","Dratini","Dragonair","Dragonite","Mewtwo","Mew","Chikorita","Bayleef","Meganium","Cyndaquil","Quilava","Typhlosion","Totodile","Croconaw","Feraligatr","Sentret","Furret","Hoothoot","Noctowl","Ledyba","Ledian","Spinarak","Ariados","Crobat","Chinchou","Lanturn","Pichu","Cleffa","Igglybuff","Togepi","Togetic","Natu","Xatu","Mareep","Flaaffy","Ampharos","Bellossom","Marill","Azumarill","Sudowoodo","Politoed","Hoppip","Skiploom","Jumpluff","Aipom","Sunkern","Sunflora","Yanma","Wooper","Quagsire","Espeon","Umbreon","Murkrow","Slowking","Misdreavus","Unown","Wobbuffet","Girafarig","Pineco","Forretress","Dunsparce","Gligar","Steelix","Snubbull","Granbull","Qwilfish","Scizor","Shuckle","Heracross","Sneasel","Teddiursa","Ursaring","Slugma","Magcargo","Swinub","Piloswine","Corsola","Remoraid","Octillery","Delibird","Mantine","Skarmory","Houndour","Houndoom","Kingdra","Phanpy","Donphan","Porygon2","Stantler","Smeargle","Tyrogue","Hitmontop","Smoochum","Elekid","Magby","Miltank","Blissey","Raikou","Entei","Suicune","Larvitar","Pupitar","Tyranitar","Lugia","Ho-Oh","Celebi","Treecko","Grovyle","Sceptile","Torchic"]
## print the number of elements in PokemonList
# print(len(PokemonList))

print("You will be a great Pokemon Master!\n ")

def calculate_entropy(file_path):
    """Calculate the Shannon entropy of a file."""
    with open(file_path, "rb") as file:
        byte_arr = file.read()
        file_size = len(byte_arr)
        if file_size == 0:
            return 0
        freq_list = [byte_arr.count(bytes([x])) / file_size for x in range(256)]
        entropy = -sum([freq * math.log2(freq) for freq in freq_list if freq > 0])
        return entropy

def append_pokemon_names_to_file(file_path):
    """Append a random Pokemon name to the end of a file."""
    with open(file_path, "a") as file:  # Open in append mode, text mode for writing words.
        pokemon_name = random.choice(PokemonList) + "\n"  # Choose a random Pokemon name and add a newline
        file.write(pokemon_name)

def reduce_entropy_with_pokemon_names(file_path, threshold=6.1):
    """Reduce the entropy of a file by appending random Pokemon names until it's below the threshold."""
    entropy = calculate_entropy(file_path)
    print(f"Initial entropy: {entropy}")
    
    while entropy > threshold:
        append_pokemon_names_to_file(file_path)
        entropy = calculate_entropy(file_path)
        # print(f"Appended a Pokemon name, new entropy: {entropy}")
    
    print(f"Final entropy: {entropy}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python entropy_reducer_with_pokemon.py <filename>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    reduce_entropy_with_pokemon_names(file_path)
